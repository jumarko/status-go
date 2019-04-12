package incentivisation

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/binary"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	gethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/status-im/status-go/mailserver/registry"
	"net"

	whisper "github.com/status-im/whisper/whisperv6"
	"time"
)

const (
	gasLimit       = 1001000
	tickerInterval = 30
)

type IncentivisationServiceConfig struct {
	RPCEndpoint     string
	ContractAddress string
	IP              string
	Port            uint16
}

type Service struct {
	w          *whisper.Whisper
	ticker     *time.Ticker
	quit       chan struct{}
	config     *IncentivisationServiceConfig
	contract   *registry.NodesV2
	privateKey *ecdsa.PrivateKey
	log        log.Logger
	// The first round we will not be voting, as we might have incomplete data
	initialSession uint64
	// The current session
	currentSession uint64
}

// New returns a new Service
func New(prv *ecdsa.PrivateKey, w *whisper.Whisper, config *IncentivisationServiceConfig) *Service {
	logger := log.New("package", "status-go/incentivisation/service")
	return &Service{
		w:          w,
		config:     config,
		privateKey: prv,
		log:        logger,
	}
}

// Protocols returns a new protocols list. In this case, there are none.
func (s *Service) Protocols() []p2p.Protocol {
	return []p2p.Protocol{}
}

func (s *Service) auth() *bind.TransactOpts {
	return bind.NewKeyedTransactor(s.privateKey)
}

// APIs returns a list of new APIs.
func (s *Service) APIs() []rpc.API {
	s.log.Info("APIS CALLED")
	apis := []rpc.API{
		{
			Namespace: "incentivisation",
			Version:   "1.0",
			Service:   NewAPI(s),
			Public:    true,
		},
	}
	return apis
}

func (s *Service) CheckRegistered() error {
	registered, err := s.Registered()
	if err != nil {
		s.log.Error("error querying contract", "registered", err)
		return err
	}

	if registered {
		s.log.Info("Already registered")
		return nil
	}
	s.log.Info("not registered")
	_, err = s.Register()
	if err != nil {
		s.log.Error("error querying contract", "registered", err)
		return err
	}
	return nil
}

func (s *Service) newSession() (bool, error) {
	session, err := s.GetCurrentSession()
	if err != nil {
		s.log.Error("failed to get current session", "err", err)
		return false, err
	}

	if session != s.currentSession {
		s.currentSession = session
		return true, nil
	}
	return false, nil
}

func (s *Service) perform() error {
	err := s.CheckRegistered()
	if err != nil {
		s.log.Error("Could not check registered", "err", err)
		return err
	}

	newSession, err := s.newSession()
	if err != nil {
		s.log.Error("Could not check session", "err", err)
		return err
	}

	if newSession {
		s.log.Info("NEW SESSION")
		return nil
	}
	s.log.Info("OLD SESSION")

	return nil
}

func (s *Service) startTicker() {
	s.ticker = time.NewTicker(tickerInterval * time.Second)
	s.quit = make(chan struct{})
	go func() {
		for {
			select {
			case <-s.ticker.C:
				s.perform()
				// do stuff
			case <-s.quit:
				s.ticker.Stop()
				return
			}
		}
	}()
}

func (s *Service) Start(server *p2p.Server) error {
	client, err := s.client()
	if err != nil {
		return err
	}

	contract, err := registry.NewNodesV2(gethcommon.HexToAddress(s.config.ContractAddress), client)
	if err != nil {
		return err
	}
	s.contract = contract
	s.log.Info("Incentivisation service started")
	s.startTicker()

	session, err := s.GetCurrentSession()
	if err != nil {
		return err
	}
	s.initialSession = session
	s.currentSession = session

	return nil
}

func (s *Service) client() (*ethclient.Client, error) {
	ethclient, err := ethclient.DialContext(context.TODO(), s.config.RPCEndpoint)
	if err != nil {
		return nil, err
	}
	return ethclient, nil
}

// Stop is run when a service is stopped.
func (s *Service) Stop() error {
	s.log.Info("Incentivisation service stopped")
	return nil
}

func (s *Service) publicKeyBytes() []byte {
	return crypto.FromECDSAPub(&s.privateKey.PublicKey)[1:]
}

func (s *Service) GetCurrentSession() (uint64, error) {
	response, err := s.contract.GetCurrentSession(nil)
	if err != nil {
		s.log.Error("failed to get current session", "err", err)
		return 0, err
	}
	return response.Uint64(), nil
}

func (s *Service) Registered() (bool, error) {
	response, err := s.contract.Registered(nil, s.publicKeyBytes())
	if err != nil {
		return false, err
	}
	return response, nil
}

func (s *Service) Register() (bool, error) {
	auth := s.auth()
	response, err := s.contract.RegisterNode(&bind.TransactOpts{
		GasLimit: gasLimit,
		From:     auth.From,
		Signer:   auth.Signer,
	}, s.publicKeyBytes(), ip2Long(s.config.IP), s.config.Port)
	if err != nil {
		return false, err
	}
	s.log.Info("resposne from registered", "response", response)
	return true, nil
}

func ip2Long(ip string) uint32 {
	var long uint32
	binary.Read(bytes.NewBuffer(net.ParseIP(ip).To4()), binary.BigEndian, &long)
	return long
}
