package main

import (
	"bytes"
	"crypto/tls"
	"encoding/xml"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"time"
)

var _ time.Time
var _ xml.Name

// AuthenticateFBA authenticates a user (and password) against the IDEiA Profiling external login web service
func AuthenticateFBA(username, password string) bool {
	ideiaProfiling := NewISP_WCF_FBA(ideiaProfilingURL, false, nil)

	utilizadorValido, err := ideiaProfiling.VerificaUtilizadorValido(&VerificaUtilizadorValido{NomeUtilizador: username, PasswordUtilizador: password})
	if err != nil {
		log.Println(err.Error())
		return false
	}
	return utilizadorValido.VerificaUtilizadorValidoResult
}

// ObtemListaUtilizadores contains the list of users
type ObtemListaUtilizadores struct {
	XMLName xml.Name `xml:"http://tempuri.org/ Obtem_ListaUtilizadores"`
}

// ObtemListaUtilizadoresResponse contains the list of users response
type ObtemListaUtilizadoresResponse struct {
	XMLName xml.Name `xml:"http://tempuri.org/ Obtem_ListaUtilizadoresResponse"`

	ObtemListaUtilizadoresResult *ArrayOfUtilizador `xml:"Obtem_ListaUtilizadoresResult,omitempty"`
}

// VerificaUtilizadorValido contains the user details
type VerificaUtilizadorValido struct {
	XMLName xml.Name `xml:"http://tempuri.org/ Verifica_UtilizadorValido"`

	NomeUtilizador string `xml:"nomeUtilizador,omitempty"`

	PasswordUtilizador string `xml:"passwordUtilizador,omitempty"`
}

type VerificaUtilizadorValidoResponse struct {
	XMLName xml.Name `xml:"http://tempuri.org/ Verifica_UtilizadorValidoResponse"`

	VerificaUtilizadorValidoResult bool `xml:"Verifica_UtilizadorValidoResult,omitempty"`
}

type CriaUtilizadorCompleto struct {
	XMLName xml.Name `xml:"http://tempuri.org/ Cria_UtilizadorCompleto"`

	NomeUtilizador string `xml:"nomeUtilizador,omitempty"`

	PasswordUtilizador string `xml:"passwordUtilizador,omitempty"`

	EmailUtilizador string `xml:"emailUtilizador,omitempty"`

	QuestaoPassword string `xml:"questaoPassword,omitempty"`

	RespostaPassword string `xml:"respostaPassword,omitempty"`
}

type CriaUtilizadorCompletoResponse struct {
	XMLName xml.Name `xml:"http://tempuri.org/ Cria_UtilizadorCompletoResponse"`

	CriaUtilizadorCompletoResult bool `xml:"Cria_UtilizadorCompletoResult,omitempty"`
}

type CriaUtilizadorSimples struct {
	XMLName xml.Name `xml:"http://tempuri.org/ Cria_UtilizadorSimples"`

	NomeUtilizador string `xml:"nomeUtilizador,omitempty"`

	EmailUtilizador string `xml:"emailUtilizador,omitempty"`
}

type CriaUtilizadorSimplesResponse struct {
	XMLName xml.Name `xml:"http://tempuri.org/ Cria_UtilizadorSimplesResponse"`

	CriaUtilizadorSimplesResult string `xml:"Cria_UtilizadorSimplesResult,omitempty"`
}

type RedefinePasswordUtilizador struct {
	XMLName xml.Name `xml:"http://tempuri.org/ Redefine_PasswordUtilizador"`

	NomeUtilizador string `xml:"nomeUtilizador,omitempty"`

	PasswordActualUtilizador string `xml:"passwordActualUtilizador,omitempty"`

	PasswordNovaUtilizador string `xml:"passwordNovaUtilizador,omitempty"`
}

type RedefinePasswordUtilizadorResponse struct {
	XMLName xml.Name `xml:"http://tempuri.org/ Redefine_PasswordUtilizadorResponse"`

	RedefinePasswordUtilizadorResult bool `xml:"Redefine_PasswordUtilizadorResult,omitempty"`
}

type RemoveUtilizador struct {
	XMLName xml.Name `xml:"http://tempuri.org/ Remove_Utilizador"`

	NomeUtilizador string `xml:"nomeUtilizador,omitempty"`
}

type RemoveUtilizadorResponse struct {
	XMLName xml.Name `xml:"http://tempuri.org/ Remove_UtilizadorResponse"`

	RemoveUtilizadorResult bool `xml:"Remove_UtilizadorResult,omitempty"`
}

type PesquisaUtilizadorAD struct {
	XMLName xml.Name `xml:"http://tempuri.org/ Pesquisa_Utilizador_AD"`

	NomePropriedadePesquisar *EnumeracaoPropriedadesAD `xml:"nomePropriedadePesquisar,omitempty"`

	ValorPropriedadePesquisar string `xml:"valorPropriedadePesquisar,omitempty"`

	PesquisaLivre bool `xml:"pesquisaLivre,omitempty"`
}

type PesquisaUtilizadorADResponse struct {
	XMLName xml.Name `xml:"http://tempuri.org/ Pesquisa_Utilizador_ADResponse"`

	PesquisaUtilizadorADResult *ArrayOfArrayOfKeyValueOfstringstring `xml:"Pesquisa_Utilizador_ADResult,omitempty"`
}

type PesquisaUtilizadorFBA struct {
	XMLName xml.Name `xml:"http://tempuri.org/ Pesquisa_Utilizador_FBA"`

	NomePropriedadePesquisar *EnumeracaoPropriedades `xml:"nomePropriedadePesquisar,omitempty"`

	ValorPropriedadePesquisar string `xml:"valorPropriedadePesquisar,omitempty"`

	PesquisaLivre bool `xml:"pesquisaLivre,omitempty"`
}

type PesquisaUtilizadorFBAResponse struct {
	XMLName xml.Name `xml:"http://tempuri.org/ Pesquisa_Utilizador_FBAResponse"`

	PesquisaUtilizadorFBAResult *ArrayOfArrayOfKeyValueOfstringstring `xml:"Pesquisa_Utilizador_FBAResult,omitempty"`
}

type VerificaUtilizadorPossuiPastaFTPHome struct {
	XMLName xml.Name `xml:"http://tempuri.org/ Verifica_UtilizadorPossuiPastaFTPHome"`

	NomeUtilizador string `xml:"nomeUtilizador,omitempty"`
}

type VerificaUtilizadorPossuiPastaFTPHomeResponse struct {
	XMLName xml.Name `xml:"http://tempuri.org/ Verifica_UtilizadorPossuiPastaFTPHomeResponse"`

	VerificaUtilizadorPossuiPastaFTPHomeResult bool `xml:"Verifica_UtilizadorPossuiPastaFTPHomeResult,omitempty"`
}

type Char int32

const ()

type Duration *Duration

const ()

type Guid string

const ()

type EnumeracaoPropriedades string

const (
	EnumeracaoPropriedadesNome EnumeracaoPropriedades = "Nome"

	EnumeracaoPropriedadesEMail EnumeracaoPropriedades = "EMail"
)

type ArrayOfUtilizador struct {
	XMLName xml.Name `xml:"http://schemas.datacontract.org/2004/07/Ferramentas.FBA ArrayOfUtilizador"`

	Utilizador []*Utilizador `xml:"Utilizador,omitempty"`
}

type Utilizador struct {
	XMLName xml.Name `xml:"http://schemas.datacontract.org/2004/07/Ferramentas.FBA Utilizador"`

	EmailUtilizador string `xml:"EmailUtilizador,omitempty"`

	NomeUtilizador string `xml:"NomeUtilizador,omitempty"`
}

type EnumeracaoPropriedadesAD string

const (
	EnumeracaoPropriedadesADNomeConta EnumeracaoPropriedadesAD = "NomeConta"

	EnumeracaoPropriedadesADNome EnumeracaoPropriedadesAD = "Nome"

	EnumeracaoPropriedadesADDescricao EnumeracaoPropriedadesAD = "Descricao"

	EnumeracaoPropriedadesADEMail EnumeracaoPropriedadesAD = "EMail"
)

type ArrayOfArrayOfKeyValueOfstringstring struct {
	XMLName xml.Name `xml:"http://schemas.microsoft.com/2003/10/Serialization/Arrays ArrayOfArrayOfKeyValueOfstringstring"`

	ArrayOfKeyValueOfstringstring []*ArrayOfKeyValueOfstringstring `xml:"ArrayOfKeyValueOfstringstring,omitempty"`
}

type ArrayOfKeyValueOfstringstring struct {
	XMLName xml.Name `xml:"http://schemas.microsoft.com/2003/10/Serialization/Arrays ArrayOfKeyValueOfstringstring"`

	KeyValueOfstringstring struct {
		Key string `xml:"Key,omitempty"`

		Value string `xml:"Value,omitempty"`
	} `xml:"KeyValueOfstringstring,omitempty"`
}

type ISP_WCF_FBA struct {
	client *SOAPClient
}

func NewISP_WCF_FBA(url string, tls bool, auth *BasicAuth) *ISP_WCF_FBA {
	if url == "" {
		url = ""
	}
	client := NewSOAPClient(url, tls, auth)

	return &ISP_WCF_FBA{
		client: client,
	}
}

func (service *ISP_WCF_FBA) SetHeader(header interface{}) {
	service.client.SetHeader(header)
}

func (service *ISP_WCF_FBA) ObtemListaUtilizadores(request *ObtemListaUtilizadores) (*ObtemListaUtilizadoresResponse, error) {
	response := new(ObtemListaUtilizadoresResponse)
	err := service.client.Call("http://tempuri.org/ISP_WCF_FBA/Obtem_ListaUtilizadores", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (service *ISP_WCF_FBA) VerificaUtilizadorValido(request *VerificaUtilizadorValido) (*VerificaUtilizadorValidoResponse, error) {
	response := new(VerificaUtilizadorValidoResponse)
	err := service.client.Call("http://tempuri.org/ISP_WCF_FBA/Verifica_UtilizadorValido", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (service *ISP_WCF_FBA) CriaUtilizadorCompleto(request *CriaUtilizadorCompleto) (*CriaUtilizadorCompletoResponse, error) {
	response := new(CriaUtilizadorCompletoResponse)
	err := service.client.Call("http://tempuri.org/ISP_WCF_FBA/Cria_UtilizadorCompleto", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (service *ISP_WCF_FBA) CriaUtilizadorSimples(request *CriaUtilizadorSimples) (*CriaUtilizadorSimplesResponse, error) {
	response := new(CriaUtilizadorSimplesResponse)
	err := service.client.Call("http://tempuri.org/ISP_WCF_FBA/Cria_UtilizadorSimples", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (service *ISP_WCF_FBA) RedefinePasswordUtilizador(request *RedefinePasswordUtilizador) (*RedefinePasswordUtilizadorResponse, error) {
	response := new(RedefinePasswordUtilizadorResponse)
	err := service.client.Call("http://tempuri.org/ISP_WCF_FBA/Redefine_PasswordUtilizador", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (service *ISP_WCF_FBA) RemoveUtilizador(request *RemoveUtilizador) (*RemoveUtilizadorResponse, error) {
	response := new(RemoveUtilizadorResponse)
	err := service.client.Call("http://tempuri.org/ISP_WCF_FBA/Remove_Utilizador", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (service *ISP_WCF_FBA) PesquisaUtilizadorAD(request *PesquisaUtilizadorAD) (*PesquisaUtilizadorADResponse, error) {
	response := new(PesquisaUtilizadorADResponse)
	err := service.client.Call("http://tempuri.org/ISP_WCF_FBA/Pesquisa_Utilizador_AD", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (service *ISP_WCF_FBA) PesquisaUtilizadorFBA(request *PesquisaUtilizadorFBA) (*PesquisaUtilizadorFBAResponse, error) {
	response := new(PesquisaUtilizadorFBAResponse)
	err := service.client.Call("http://tempuri.org/ISP_WCF_FBA/Pesquisa_Utilizador_FBA", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (service *ISP_WCF_FBA) VerificaUtilizadorPossuiPastaFTPHome(request *VerificaUtilizadorPossuiPastaFTPHome) (*VerificaUtilizadorPossuiPastaFTPHomeResponse, error) {
	response := new(VerificaUtilizadorPossuiPastaFTPHomeResponse)
	err := service.client.Call("http://tempuri.org/ISP_WCF_FBA/Verifica_UtilizadorPossuiPastaFTPHome", request, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

var timeout = time.Duration(30 * time.Second)

func dialTimeout(network, addr string) (net.Conn, error) {
	return net.DialTimeout(network, addr, timeout)
}

type SOAPEnvelope struct {
	XMLName xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Envelope"`
	Header  *SOAPHeader
	Body    SOAPBody
}

type SOAPHeader struct {
	XMLName xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Header"`

	Header interface{}
}

type SOAPBody struct {
	XMLName xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Body"`

	Fault   *SOAPFault  `xml:",omitempty"`
	Content interface{} `xml:",omitempty"`
}

type SOAPFault struct {
	XMLName xml.Name `xml:"http://schemas.xmlsoap.org/soap/envelope/ Fault"`

	Code   string `xml:"faultcode,omitempty"`
	String string `xml:"faultstring,omitempty"`
	Actor  string `xml:"faultactor,omitempty"`
	Detail string `xml:"detail,omitempty"`
}

type BasicAuth struct {
	Login    string
	Password string
}

type SOAPClient struct {
	url    string
	tls    bool
	auth   *BasicAuth
	header interface{}
}

func (b *SOAPBody) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	if b.Content == nil {
		return xml.UnmarshalError("Content must be a pointer to a struct")
	}

	var (
		token    xml.Token
		err      error
		consumed bool
	)

Loop:
	for {
		if token, err = d.Token(); err != nil {
			return err
		}

		if token == nil {
			break
		}

		switch se := token.(type) {
		case xml.StartElement:
			if consumed {
				return xml.UnmarshalError("Found multiple elements inside SOAP body; not wrapped-document/literal WS-I compliant")
			} else if se.Name.Space == "http://schemas.xmlsoap.org/soap/envelope/" && se.Name.Local == "Fault" {
				b.Fault = &SOAPFault{}
				b.Content = nil

				err = d.DecodeElement(b.Fault, &se)
				if err != nil {
					return err
				}

				consumed = true
			} else {
				if err = d.DecodeElement(b.Content, &se); err != nil {
					return err
				}

				consumed = true
			}
		case xml.EndElement:
			break Loop
		}
	}

	return nil
}

func (f *SOAPFault) Error() string {
	return f.String
}

func NewSOAPClient(url string, tls bool, auth *BasicAuth) *SOAPClient {
	return &SOAPClient{
		url:  url,
		tls:  tls,
		auth: auth,
	}
}

func (s *SOAPClient) SetHeader(header interface{}) {
	s.header = header
}

func (s *SOAPClient) Call(soapAction string, request, response interface{}) error {
	envelope := SOAPEnvelope{}

	if s.header != nil {
		envelope.Header = &SOAPHeader{Header: s.header}
	}

	envelope.Body.Content = request
	buffer := new(bytes.Buffer)

	encoder := xml.NewEncoder(buffer)
	//encoder.Indent("  ", "    ")

	if err := encoder.Encode(envelope); err != nil {
		return err
	}

	if err := encoder.Flush(); err != nil {
		return err
	}

	log.Println(buffer.String())

	req, err := http.NewRequest("POST", s.url, buffer)
	if err != nil {
		return err
	}
	if s.auth != nil {
		req.SetBasicAuth(s.auth.Login, s.auth.Password)
	}

	req.Header.Add("Content-Type", "text/xml; charset=\"utf-8\"")
	if soapAction != "" {
		req.Header.Add("SOAPAction", soapAction)
	}

	req.Header.Set("User-Agent", "gowsdl/0.1")
	req.Close = true

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: s.tls,
		},
		Dial: dialTimeout,
	}

	client := &http.Client{Transport: tr}
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	rawbody, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return err
	}
	if len(rawbody) == 0 {
		log.Println("empty response")
		return nil
	}

	log.Println(string(rawbody))
	respEnvelope := new(SOAPEnvelope)
	respEnvelope.Body = SOAPBody{Content: response}
	err = xml.Unmarshal(rawbody, respEnvelope)
	if err != nil {
		return err
	}

	fault := respEnvelope.Body.Fault
	if fault != nil {
		return fault
	}

	return nil
}
