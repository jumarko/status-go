package incentivisation

import (
	"bytes"
	"context"
	"errors"

	"crypto/ecdsa"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	gethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/status-im/status-go/mailserver/registry"
	"math/big"
	"net"
	"sort"

	whisper "github.com/status-im/whisper/whisperv6"
	"time"
)

const (
	gasLimit              = 1001000
	pingIntervalAllowance = 240
	tickerInterval        = 30
	defaultTopic          = "status-incentivisation-topic"
)

type Enode struct {
	PublicKey      []byte
	IP             net.IP
	Port           uint16
	JoiningSession uint32
	ActiveSession  uint32
	Active         bool
}

func formatEnodeURL(publicKey string, ip string, port uint16) string {
	return fmt.Sprintf("enode://%s:%s:%d", publicKey, ip, port)
}

func (n *Enode) toEnodeURL() string {
	return formatEnodeURL(n.PublicKeyString(), n.IP.String(), n.Port)
}

func (n *Enode) PublicKeyString() string {
	return hex.EncodeToString(n.PublicKey)
}

type IncentivisationServiceConfig struct {
	RPCEndpoint     string
	ContractAddress string
	IP              string
	Port            uint16
}

type Service struct {
	w               *whisper.PublicWhisperAPI
	whisperKeyID    string
	whisperSymKeyID string
	whisperFilterID string
	nodes           map[string]*Enode
	ticker          *time.Ticker
	quit            chan struct{}
	config          *IncentivisationServiceConfig
	contract        *registry.NodesV2
	privateKey      *ecdsa.PrivateKey
	log             log.Logger
	// The first round we will not be voting, as we might have incomplete data
	initialSession uint64
	// The current session
	currentSession uint64
	whisperPings   map[string][]uint32
}

// New returns a new Service
func New(prv *ecdsa.PrivateKey, w *whisper.Whisper, config *IncentivisationServiceConfig) *Service {
	logger := log.New("package", "status-go/incentivisation/service")
	return &Service{
		w:            whisper.NewPublicWhisperAPI(w),
		config:       config,
		privateKey:   prv,
		log:          logger,
		nodes:        make(map[string]*Enode),
		whisperPings: make(map[string][]uint32),
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

func (s *Service) CheckPings() map[string]bool {
	result := make(map[string]bool)
	now := time.Now().Unix()
	s.log.Info("checking votes", "votes", s.whisperPings)
	for enodeID, timestamps := range s.whisperPings {
		result[enodeID] = true

		if len(timestamps) < 2 {
			s.log.Info("Node failed check", "enodeID", enodeID)
			result[enodeID] = false
			continue
		}

		sort.Slice(timestamps, func(i, j int) bool { return timestamps[i] < timestamps[j] })
		timestamps = append(timestamps, uint32(now))
		for i := 1; i < len(timestamps); i++ {
			s.log.Info("Diff", "t1", timestamps[i], "t2", timestamps[i-1], "t1-t2", timestamps[i]-timestamps[i-1])

			if timestamps[i]-timestamps[i-1] > pingIntervalAllowance {
				result[enodeID] = false
			}
		}
		if result[enodeID] {
			s.log.Info("Node passed check", "enodeID", enodeID)
		} else {
			s.log.Info("Node failed check", "enodeID", enodeID)
		}

	}
	s.log.Info("voting result", "result", result)
	return result
}

func (s *Service) perform() error {
	hash, err := s.PostPing()
	if err != nil {
		s.log.Error("Could not post ping", "err", err)
		return err
	}
	s.log.Info("Posted ping", "hash", hash)

	err = s.FetchEnodes()
	if err != nil {
		return err
	}

	err = s.FetchMessages()
	if err != nil {
		return err
	}

	err = s.CheckRegistered()
	if err != nil {
		s.log.Error("Could not check registered", "err", err)
		return err
	}

	// This actually updates the session
	newSession, err := s.newSession()
	if err != nil {
		s.log.Error("Could not check session", "err", err)
		return err
	}

	if !newSession {
		s.log.Info("Not a new session idling")
		return nil
	}

	result := s.CheckPings()
	err = s.vote(result)
	if err != nil {
		s.log.Error("Could not vote", "err", err)
		return err
	}

	// Reset whisper pings
	s.whisperPings = make(map[string][]uint32)

	return nil
}

func (s *Service) vote(result map[string]bool) error {
	var behavingNodes []gethcommon.Address
	var misbehavingNodes []gethcommon.Address
	auth := s.auth()

	for enodeIDString, passedCheck := range result {
		enodeID, err := hex.DecodeString(enodeIDString)
		if err != nil {
			return err
		}
		if passedCheck {
			behavingNodes = append(behavingNodes, publicKeyBytesToAddress(enodeID))
		} else {
			misbehavingNodes = append(misbehavingNodes, publicKeyBytesToAddress(enodeID))
		}
	}

	tx, err := s.contract.Vote(&bind.TransactOpts{
		GasLimit: gasLimit,
		From:     auth.From,
		Signer:   auth.Signer,
	}, behavingNodes, misbehavingNodes)
	client, err := s.client()
	for true {
		receipt, _ := client.TransactionReceipt(context.TODO(), tx.Hash())
		if receipt != nil {
			if receipt.Status == 0 {
				s.log.Info("Receipt returned 0 status")
				return errors.New("Receipt invalid")
			} else {
				s.log.Info("Receipt returned non-zero status", "status", receipt.Status)
				break
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return err
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

	s.log.Info("Incentivisation service started 2", "address", s.addressString(), "publickey", s.publicKeyString())
	s.startTicker()

	session, err := s.GetCurrentSession()
	if err != nil {
		return err
	}
	s.initialSession = session
	s.currentSession = session

	whisperKeyID, err := s.w.AddPrivateKey(context.TODO(), crypto.FromECDSA(s.privateKey))
	if err != nil {
		return err
	}

	s.whisperKeyID = whisperKeyID

	whisperSymKeyID, err := s.w.GenerateSymKeyFromPassword(context.TODO(), defaultTopic)

	if err != nil {
		return err
	}
	s.whisperSymKeyID = whisperSymKeyID

	criteria := whisper.Criteria{
		SymKeyID: whisperSymKeyID,
		Topics:   []whisper.TopicType{toWhisperTopic(defaultTopic)},
	}
	filterID, err := s.w.NewMessageFilter(criteria)
	if err != nil {
		s.log.Error("could not create filter", "err", err)
		return err
	}
	s.whisperFilterID = filterID

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
	s.w.DeleteKeyPair(context.TODO(), s.whisperKeyID)

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

func (s *Service) FetchEnodes() error {
	one := big.NewInt(1)

	activeNodeCount, err := s.contract.ActiveNodeCount(nil)
	if err != nil {
		return err
	}
	s.log.Info("fetched node count", "count", activeNodeCount)
	for i := big.NewInt(0); i.Cmp(activeNodeCount) < 0; i.Add(i, one) {
		publicKey, ip, port, joiningSession, activeSession, err := s.contract.GetNode(nil, i)
		if err != nil {
			return err
		}

		node := &Enode{
			PublicKey:      publicKey,
			IP:             int2ip(ip),
			Port:           port,
			JoiningSession: joiningSession,
			ActiveSession:  activeSession,
		}

		s.log.Info("adding node", "node", node.toEnodeURL())
		if node.PublicKeyString() != s.publicKeyString() {
			s.nodes[node.PublicKeyString()] = node
		}
	}

	inactiveNodeCount, err := s.contract.InactiveNodeCount(nil)
	if err != nil {
		return err
	}
	s.log.Info("fetched node count", "count", inactiveNodeCount)
	for i := big.NewInt(0); i.Cmp(inactiveNodeCount) < 0; i.Add(i, one) {
		publicKey, ip, port, joiningSession, activeSession, err := s.contract.GetInactiveNode(nil, i)
		if err != nil {
			return err
		}

		node := &Enode{
			PublicKey:      publicKey,
			IP:             int2ip(ip),
			Port:           port,
			JoiningSession: joiningSession,
			ActiveSession:  activeSession,
		}

		s.log.Info("adding node", "node", node.toEnodeURL())
		if node.PublicKeyString() != s.publicKeyString() {
			s.nodes[node.PublicKeyString()] = node
		}
	}

	return nil

}

func (s *Service) publicKeyString() string {
	return hex.EncodeToString(s.publicKeyBytes())
}

func (s *Service) addressString() string {
	buf := crypto.Keccak256Hash(s.publicKeyBytes())
	address := buf[12:]

	return hex.EncodeToString(address)

	return hex.EncodeToString(s.publicKeyBytes())
}

func (s *Service) PostPing() (hexutil.Bytes, error) {
	msg := defaultWhisperMessage()

	msg.Topic = toWhisperTopic(defaultTopic)

	enodeURL := formatEnodeURL(s.publicKeyString(), s.config.IP, s.config.Port)
	payload, err := EncodeMessage(enodeURL, defaultTopic)
	if err != nil {
		return nil, err
	}

	msg.Payload = payload
	msg.Sig = s.whisperKeyID
	msg.SymKeyID = s.whisperSymKeyID

	return s.w.Post(context.TODO(), msg)
}

func (s *Service) FetchMessages() error {
	messages, err := s.w.GetFilterMessages(s.whisperFilterID)
	if err != nil {
		return err
	}

	s.log.Info("fetched messages", "count", len(messages))
	for i := 0; i < len(messages); i++ {
		signature := hex.EncodeToString(messages[i].Sig[1:])
		timestamp := messages[i].Timestamp
		if s.nodes[signature] != nil {
			s.whisperPings[signature] = append(s.whisperPings[signature], timestamp)
		}
		s.log.Info("signature of message", "signature", signature)
	}
	return nil
}

func ip2Long(ip string) uint32 {
	var long uint32
	binary.Read(bytes.NewBuffer(net.ParseIP(ip).To4()), binary.BigEndian, &long)
	return long
}

func toWhisperTopic(s string) whisper.TopicType {
	return whisper.BytesToTopic(crypto.Keccak256([]byte(s)))
}

func defaultWhisperMessage() whisper.NewMessage {
	msg := whisper.NewMessage{}

	msg.TTL = 10
	msg.PowTarget = 0.002
	msg.PowTime = 1

	return msg
}

func int2ip(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, nn)
	return ip
}

func publicKeyBytesToAddress(publicKey []byte) gethcommon.Address {
	buf := crypto.Keccak256Hash(publicKey)
	address := buf[12:]

	return gethcommon.HexToAddress(hex.EncodeToString(address))
}
