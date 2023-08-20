package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/fatih/color"
	"github.com/google/uuid"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttpproxy"
	"golang.org/x/sys/windows"
)

var claimedtokens = make(chan string)
var failedtokens = make(chan string)
var failedvcc = make(chan string)
var failedpromo = make(chan string)
var grey = color.New(color.FgHiMagenta).SprintFunc()
var claimedint int
var failed int
var threadlock sync.Mutex

type Redeemer struct {
	Token                    string
	Vccnum                   string
	Expmonth                 string
	Expyear                  string
	Vcccvv                   string
	Useragent                string
	Muid                     string
	Guid                     string
	Sid                      string
	Fingerprint              string
	Superproperties          string
	Cookies                  string
	UserId                   string
	UserName                 string
	TokenId                  string
	ClientSecret             string
	AddressToken             string
	PaymentMethod            string
	CardId                   string
	Promo                    string
	StripePaymentId          string
	StripeIntentId           string
	DispatchedStripeIntentId string
	ThreeDSecure2Source      string
	TransactionID            string
	TokenFull                string
	Client                   fasthttp.Client
}

func (c *Redeemer) superproperties() error {
	type SuperProperties struct {
		OS                  string `json:"os"`
		Browser             string `json:"browser"`
		Device              string `json:"device"`
		SystemLocale        string `json:"system_locale"`
		BrowserUserAgent    string `json:"browser_user_agent"`
		BrowserVersion      string `json:"browser_version"`
		OSVersion           string `json:"os_version"`
		Referrer            string `json:"referrer"`
		ReferringDomain     string `json:"referring_domain"`
		ReferrerCurrent     string `json:"referrer_current"`
		ReferringDomainCurr string `json:"referring_domain_current"`
		ReleaseChannel      string `json:"release_channel"`
		ClientBuildNumber   int    `json:"client_build_number"`
		ClientEventSource   string `json:"client_event_source,omitempty"`
	}
	data := SuperProperties{
		OS:                "Windows",
		Browser:           "Chrome",
		SystemLocale:      "en-US",
		BrowserUserAgent:  c.Useragent,
		BrowserVersion:    "114.0.0.0",
		OSVersion:         "10",
		ReleaseChannel:    "stable",
		ClientBuildNumber: 211644,
	}
	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}
	c.Superproperties = base64.StdEncoding.EncodeToString(jsonData)
	printProgress("[*] SuperProperties: " + c.Superproperties)
	return nil
}
func (c *Redeemer) fingerprintncookies() error {
	req := fasthttp.AcquireRequest()
	req.SetRequestURIBytes([]byte(`https://discord.com/api/v9/experiments?with_guild_experiments=true`))
	req.Header.SetMethod(fasthttp.MethodGet)
	req.Header.Set(`authority`, `discord.com`)
	req.Header.Set(`method`, `GET`)
	req.Header.Set(`path`, `/api/v9/experiments?with_guild_experiments=true`)
	req.Header.Set(`scheme`, `https`)
	req.Header.Set(`Accept`, `*/*`)
	req.Header.Set(`Accept-Encoding`, `br`)
	req.Header.Set(`Accept-Language`, `en-GB,en-US;q=0.9,en;q=0.8`)
	req.Header.Set(`Content-Type`, `application/json`)
	req.Header.Set(`Origin`, `https,//discord.com`)
	req.Header.Set(`Referer`, `https,//discord.com/channels/@me`)
	req.Header.Set(`Sec-Ch-Ua`, `Not/A)Brand";v="99", "Google Chrome";v="115", "Chromium";v="115`)
	req.Header.Set(`Sec-Ch-Ua-Mobile`, `?1`)
	req.Header.Set(`Sec-Ch-Ua-Platform`, `"Windows"`)
	req.Header.Set(`Sec-Fetch-Dest`, `empty`)
	req.Header.Set(`Sec-Fetch-Mode`, `cors`)
	req.Header.Set(`sec-fetch-site`, `same-origin`)
	req.Header.Set(`User-Agent`, c.Useragent)
	req.Header.Set(`X-Debug-Options`, `bugReporterEnabled`)
	req.Header.Set(`X-Discord-Locale`, `en-US`)
	req.Header.Set(`X-Discord-Timezone`, `Asia/Calcutta`)
	req.Header.Set(`X-Super-Properties`, c.Superproperties)
	resp := fasthttp.AcquireResponse()
	for {
		printProgress("[+] Getting FingerPrint & Cookies")
		err := c.Client.Do(req, resp)
		if err != nil {
			printProgress("Failed: " + err.Error())
			printProgress("Retrying...")
			continue
		}
		break
	}
	var fingerprintstruct struct {
		Fingerprint string `json:"fingerprint"`
	}
	body, err := resp.BodyUnbrotli()
	if err != nil {
		return err
	}
	if resp.StatusCode() == 200 || resp.StatusCode() == 201 || resp.StatusCode() == 204 {
		err := json.Unmarshal(body, &fingerprintstruct)
		if err != nil {
			return err
		}
		c.Fingerprint = fingerprintstruct.Fingerprint
		__cfruid := strings.Split(string(resp.Header.PeekCookie("__cfruid")), ";")[0]
		__dcfduid := strings.Split(string(resp.Header.PeekCookie("__dcfduid")), ";")[0]
		__sdcfduid := strings.Split(string(resp.Header.PeekCookie("__sdcfduid")), ";")[0]
		c.Cookies = fmt.Sprintf("%s; %s; %s; locale=en-US;", __dcfduid, __cfruid, __sdcfduid)
		printProgress("[*] FingerPrint: " + c.Fingerprint)
		printProgress("[*] Cookies: " + c.Cookies)
		return nil
	} else {
		return errors.New("failed to get cookies and fingerprint")
	}
}
func (c *Redeemer) checktoken() error {
	req := fasthttp.AcquireRequest()
	req.SetRequestURIBytes([]byte(`https://discord.com/api/v9/users/@me`))
	req.Header.SetMethod(fasthttp.MethodGet)
	req.Header.Set(`Accept`, `*/*`)
	req.Header.Set(`Accept-Language`, `en-GB,en-US;q=0.9,en;q=0.8`)
	req.Header.Set(`Accept-Encoding`, `br`)
	req.Header.Set(`Authorization`, c.Token)
	req.Header.Set(`Content-Type`, `application/json`)
	req.Header.Set(`Cookie`, c.Cookies)
	req.Header.Set(`Origin`, `https://discord.com`)
	req.Header.Set(`Referer`, `https://discord.com`)
	req.Header.Set(`Sec-Ch-Ua`, `Not/A)Brand";v="99", "Google Chrome";v="115", "Chromium";v="115`)
	req.Header.Set(`Sec-Ch-Ua-Mobile`, `?1`)
	req.Header.Set(`Sec-Ch-Ua-Platform`, `"Windows"`)
	req.Header.Set(`Sec-Fetch-Dest`, `empty`)
	req.Header.Set(`Sec-Fetch-Mode`, `cors`)
	req.Header.Set(`sec-fetch-site`, `same-origin`)
	req.Header.Set(`User-Agent`, c.Useragent)
	req.Header.Set(`X-Debug-Options`, `bugReporterEnabled`)
	req.Header.Set(`X-Discord-Locale`, `en-US`)
	req.Header.Set(`X-Discord-Timezone`, `Asia/Calcutta`)
	req.Header.Set(`x-context-properties`, `eyJsb2NhdGlvbiI6Ii9jaGFubmVscy9AbWUifQ==`)
	req.Header.Set(`X-Super-Properties`, c.Superproperties)
	req.Header.Set(`fingerprint`, c.Fingerprint)
	resp := fasthttp.AcquireResponse()
	for {
		printProgress("[+] Checking Token")
		err := c.Client.Do(req, resp)
		if err != nil {
			printProgress("Failed: " + err.Error())
			printProgress("Retrying...")
			continue
		}
		break
	}
	var acc struct {
		Username    string `json:"username"`
		Id          string `json:"id"`
		PremiumType int    `json:"premium_type"`
	}
	if resp.StatusCode() == 200 {
		body, err := resp.BodyUnbrotli()
		if err != nil {
			return err
		}
		err = json.Unmarshal(body, &acc)
		if err != nil {
			return err
		}
		if acc.PremiumType == 2 || acc.PremiumType == 3 {
			failedtokens <- c.TokenFull
			return errors.New("account already have nitro")
		}
		c.UserId = acc.Id
		c.UserName = acc.Username
		fmt.Printf("["+grey(time.Now().Format("15:04:05"))+"] \033[38;5;83m[+] Redeeming on -> %s\033[0m\n", c.UserName)
		return nil
	} else if strings.Contains(string(resp.Body()), "401: Unauthorized") {
		failedtokens <- c.TokenFull
		return errors.New("account invalid")
	} else if strings.Contains(string(resp.Body()), "You need to verify your account in order to perform this action") {
		failedtokens <- c.TokenFull
		return errors.New("account locked")
	} else {
		failedtokens <- c.TokenFull
		printNetworkError(resp.StatusCode(), fmt.Sprintf("Token -> %s********", c.Token[:20]), string(resp.Body()))
		return errors.New("unknown token error")
	}
}

func (c *Redeemer) ctokenize() error {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	formData := url.Values{
		"card[number]":       []string{c.Vccnum},
		"card[cvc]":          []string{c.Vcccvv},
		"card[exp_month]":    []string{c.Expmonth},
		"card[exp_year]":     []string{c.Expyear},
		"guid":               []string{c.Guid},
		"muid":               []string{c.Muid},
		"sid":                []string{c.Sid},
		"payment_user_agent": []string{"stripe.js/5fa73ff167; stripe-js-v3/5fa73ff167; split-card-element"},
		"time_on_page":       []string{strconv.Itoa(r.Intn(10000) + 10000)},
		"key":                []string{"pk_live_CUQtlpQUF0vufWpnpUmQvcdi"},
		"pasted_fields":      []string{"number,exp"},
	}
	req := fasthttp.AcquireRequest()
	req.SetRequestURIBytes([]byte(`https://api.stripe.com/v1/tokens`))
	req.Header.SetMethod(fasthttp.MethodPost)
	req.Header.Set(`authority`, `api.stripe.com`)
	req.Header.Set(`accept`, `application/json`)
	req.Header.Set(`accept-language`, `en-US`)
	req.Header.Set(`content-type`, `application/x-www-form-urlencoded`)
	req.Header.Set(`origin`, `https,//js.stripe.com`)
	req.Header.Set(`referer`, `https,//js.stripe.com/`)
	req.Header.Set(`sec-ch-ua`, `"Not?A_Brand";v="8", "Chromium";v="108"`)
	req.Header.Set(`sec-ch-ua-mobile`, `?0`)
	req.Header.Set(`sec-ch-ua-platform`, `"Windows"`)
	req.Header.Set(`sec-fetch-dest`, `empty`)
	req.Header.Set(`sec-fetch-mode`, `cors`)
	req.Header.Set(`sec-fetch-site`, `same-site`)
	req.Header.Set(`user-agent`, c.Useragent)
	req.SetBodyRaw([]byte(formData.Encode()))
	resp := fasthttp.AcquireResponse()
	for {
		printProgress("[+] Getting CCToken")
		err := c.Client.Do(req, resp)
		if err != nil {
			printProgress("Failed : " + err.Error())
			printProgress("Retrying...")
			continue
		}
		break
	}
	if resp.StatusCode() == 200 {
		var ctoken struct {
			TokenId string `json:"id"`
		}
		err := json.Unmarshal(resp.Body(), &ctoken)
		if err != nil {
			return err
		}
		c.TokenId = ctoken.TokenId
		printProgress("[*] CTokenized: " + c.TokenId)
		return nil
	} else {
		printNetworkError(resp.StatusCode(), fmt.Sprintf("CTokenize -> xxxxxx%s", c.Vccnum[6:]), string(resp.Body()))
		failedvcc <- fmt.Sprintf("%s:%s%s:%s", c.Vccnum, c.Expmonth, c.Expyear, c.Vcccvv)
		return errors.New("error occured in cctoknization")
	}
}

func (c *Redeemer) csetupintents() error {
	req := fasthttp.AcquireRequest()
	req.SetRequestURIBytes([]byte("https://discord.com/api/v9/users/@me/billing/stripe/setup-intents"))
	req.Header.SetMethod(fasthttp.MethodPost)
	req.Header.Set(`Accept`, `*/*`)
	req.Header.Set(`Accept-Encoding`, `br`)
	req.Header.Set(`Accept-Language`, `en-GB,en-US;q=0.9,en;q=0.8`)
	req.Header.Set(`Authorization`, c.Token)
	req.Header.Set(`Content-Type`, `application/json`)
	req.Header.Set(`Cookie`, c.Cookies)
	req.Header.Set(`Origin`, `https://discord.com`)
	req.Header.Set(`Referer`, `https://discord.com`)
	req.Header.Set(`Sec-Ch-Ua`, `Not/A)Brand";v="99", "Google Chrome";v="115", "Chromium";v="115`)
	req.Header.Set(`Sec-Ch-Ua-Mobile`, `?1`)
	req.Header.Set(`Sec-Ch-Ua-Platform`, `"Windows"`)
	req.Header.Set(`Sec-Fetch-Dest`, `empty`)
	req.Header.Set(`Sec-Fetch-Mode`, `cors`)
	req.Header.Set(`sec-fetch-site`, `same-origin`)
	req.Header.Set(`User-Agent`, c.Useragent)
	req.Header.Set(`X-Debug-Options`, `bugReporterEnabled`)
	req.Header.Set(`X-Discord-Locale`, `en-US`)
	req.Header.Set(`X-Discord-Timezone`, `Asia/Calcutta`)
	req.Header.Set(`x-context-properties`, `eyJsb2NhdGlvbiI6Ii9jaGFubmVscy9AbWUifQ==`)
	req.Header.Set(`X-Super-Properties`, c.Superproperties)
	req.Header.Set(`fingerprint`, c.Fingerprint)
	resp := fasthttp.AcquireResponse()
	for {
		printProgress("[+] Getting SetupIntents")
		err := c.Client.Do(req, resp)
		if err != nil {
			printNetworkError(0, "SetupIntents", err.Error())
			printProgress("Retrying...")
			continue
		}
		break
	}
	if resp.StatusCode() == 200 {
		body, err := resp.BodyUnbrotli()
		if err != nil {
			return err
		}
		var csetupintent struct {
			ClientSecret string `json:"client_secret"`
		}
		err = json.Unmarshal(body, &csetupintent)
		if err != nil {
			return err
		}
		c.ClientSecret = csetupintent.ClientSecret
		printProgress("[*] ClientSecret: " + c.ClientSecret)
		return nil
	} else {
		printNetworkError(resp.StatusCode(), fmt.Sprintf("CSetupintents -> xxxxxx%s", c.Vccnum[6:]), string(resp.Body()))
		failedvcc <- fmt.Sprintf("%s:%s%s:%s", c.Vccnum, c.Expmonth, c.Expyear, c.Vcccvv)
		return errors.New("something went wrong on csetupintent")
	}
}

func (c *Redeemer) validatebilling() error {
	type ValidateBillingBody struct {
		Billing struct {
			Name       string `json:"name"`
			Line1      string `json:"line_1"`
			Line2      string `json:"line_2"`
			City       string `json:"city"`
			State      string `json:"state"`
			PostalCode string `json:"postal_code"`
			Country    string `json:"country"`
			Email      string `json:"email"`
		} `json:"billing_address"`
	}
	BodyBill := ValidateBillingBody{
		Billing: struct {
			Name       string `json:"name"`
			Line1      string `json:"line_1"`
			Line2      string `json:"line_2"`
			City       string `json:"city"`
			State      string `json:"state"`
			PostalCode string `json:"postal_code"`
			Country    string `json:"country"`
			Email      string `json:"email"`
		}{
			Name:       "Null UwU",
			Line1:      "Delhi",
			Line2:      "Delhi",
			City:       "Delhi",
			State:      "Delhi",
			PostalCode: "10001",
			Country:    "KR",
			Email:      "",
		},
	}
	bodyval, err := json.Marshal(BodyBill)
	if err != nil {
		return err
	}
	req := fasthttp.AcquireRequest()
	req.SetRequestURIBytes([]byte(`https://discord.com/api/v9/users/@me/billing/payment-sources/validate-billing-address`))
	req.Header.SetMethod(fasthttp.MethodPost)
	req.Header.Set(`Accept`, `*/*`)
	req.Header.Set(`Accept-Language`, `en-GB,en-US;q=0.9,en;q=0.8`)
	req.Header.Set(`Authorization`, c.Token)
	req.Header.Set(`Content-Type`, `application/json`)
	req.Header.Set(`Cookie`, c.Cookies)
	req.Header.Set(`Origin`, `https://discord.com`)
	req.Header.Set(`Referer`, `https://discord.com/channels/@me`)
	req.Header.Set(`Sec-Ch-Ua`, `Not/A)Brand";v="99", "Google Chrome";v="115", "Chromium";v="115`)
	req.Header.Set(`Sec-Ch-Ua-Mobile`, `?1`)
	req.Header.Set(`Sec-Ch-Ua-Platform`, `"Windows"`)
	req.Header.Set(`Sec-Fetch-Dest`, `empty`)
	req.Header.Set(`Sec-Fetch-Mode`, `cors`)
	req.Header.Set(`sec-fetch-site`, `same-origin`)
	req.Header.Set(`User-Agent`, c.Useragent)
	req.Header.Set(`X-Debug-Options`, `bugReporterEnabled`)
	req.Header.Set(`X-Discord-Locale`, `en-US`)
	req.Header.Set(`X-Discord-Timezone`, `Asia/Calcutta`)
	req.Header.Set(`x-context-properties`, `eyJsb2NhdGlvbiI6Ii9jaGFubmVscy9AbWUifQ==`)
	req.Header.Set(`X-Super-Properties`, c.Superproperties)
	req.Header.Set(`fingerprint`, c.Fingerprint)
	req.SetBodyRaw(bodyval)
	resp := fasthttp.AcquireResponse()
	for {
		printProgress("[+] Getting AddressToken")
		err := c.Client.Do(req, resp)
		if err != nil {
			printNetworkError(0, "ValidateBilling", err.Error())
			printProgress("Retrying...")
			continue
		}
		break
	}
	if resp.StatusCode() == 200 {
		var address struct {
			AddressToken string `json:"token"`
		}
		err = json.Unmarshal(resp.Body(), &address)
		if err != nil {
			return err
		}
		c.AddressToken = address.AddressToken
		printProgress("[+] AddressToken: " + c.AddressToken)
		return nil
	} else {
		printNetworkError(resp.StatusCode(), fmt.Sprintf("Validatebilling -> xxxxxx%s", c.Vccnum[6:]), string(resp.Body()))
		failedvcc <- fmt.Sprintf("%s:%s%s:%s", c.Vccnum, c.Expmonth, c.Expyear, c.Vcccvv)
		return errors.New("something went wrong with validatebilling")
	}
}

func (c *Redeemer) cpaymentConfirm() error {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	data := url.Values{
		"payment_method_data[type]":                                  {"card"},
		"payment_method_data[card][token]":                           {c.TokenId},
		"payment_method_data[billing_details][address][line1]":       {"Delhi"},
		"payment_method_data[billing_details][address][line2]":       {"Delhi"},
		"payment_method_data[billing_details][address][city]":        {"Delhi"},
		"payment_method_data[billing_details][address][state]":       {"Delhi"},
		"payment_method_data[billing_details][address][postal_code]": {"10001"},
		"payment_method_data[billing_details][address][country]":     {"KR"},
		"payment_method_data[billing_details][name]":                 {"Null UwU"},
		"payment_method_data[guid]":                                  {c.Guid},
		"payment_method_data[muid]":                                  {c.Muid},
		"payment_method_data[sid]":                                   {c.Sid},
		"payment_method_data[payment_user_agent]":                    {"stripe.js/5fa73ff167; stripe-js-v3/5fa73ff167"},
		"payment_method_data[time_on_page]":                          {strconv.Itoa(r.Intn(10000) + 10000)},
		"expected_payment_method_type":                               {"card"},
		"use_stripe_sdk":                                             {"true"},
		"key":                                                        {"pk_live_CUQtlpQUF0vufWpnpUmQvcdi"},
		"client_secret":                                              {c.ClientSecret},
	}
	req := fasthttp.AcquireRequest()
	req.Header.SetRequestURIBytes([]byte(`https://api.stripe.com/v1/setup_intents/` + strings.Split(c.ClientSecret, "_secret")[0] + `/confirm`))
	req.Header.SetMethod(fasthttp.MethodPost)
	req.Header.Set("authority", "api.stripe.com")
	req.Header.Set("accept", "application/json")
	req.Header.Set("accept-language", "en-US,en;q=0.9")
	req.Header.Set("cache-control", "no-cache")
	req.Header.Set("content-type", "application/x-www-form-urlencoded")
	req.Header.Set("origin", "https://js.stripe.com")
	req.Header.Set("pragma", "no-cache")
	req.Header.Set("referer", "https://js.stripe.com/")
	req.Header.Set("sec-ch-ua", `"Not.A/Brand";v="8", "Chromium";v="114", "Google Chrome";v="114"`)
	req.Header.Set("sec-ch-ua-mobile", "?0")
	req.Header.Set("sec-ch-ua-platform", `"Linux"`)
	req.Header.Set("sec-fetch-dest", "empty")
	req.Header.Set("sec-fetch-mode", "cors")
	req.Header.Set("sec-fetch-site", "same-site")
	req.Header.Set("user-agent", c.Useragent)
	req.SetBodyRaw([]byte(data.Encode()))
	resp := fasthttp.AcquireResponse()
	for {
		printProgress("Getting PaymentMethod")
		err := c.Client.Do(req, resp)
		if err != nil {
			printNetworkError(0, "CPaymentConfirm", err.Error())
			printProgress("Retrying...")
			continue
		}
		break
	}
	if resp.StatusCode() == 200 {
		var payment_method struct {
			PaymentMethod string `json:"payment_method"`
		}
		err := json.Unmarshal(resp.Body(), &payment_method)
		if err != nil {
			return err
		}
		c.PaymentMethod = payment_method.PaymentMethod
		printProgress("[+] PaymentMethod: " + c.PaymentMethod)
		return nil
	} else {
		printNetworkError(resp.StatusCode(), fmt.Sprintf("CPaymentconfirm -> xxxxxx%s", c.Vccnum[6:]), string(resp.Body()))
		failedvcc <- fmt.Sprintf("%s:%s%s:%s", c.Vccnum, c.Expmonth, c.Expyear, c.Vcccvv)
		return errors.New("something went wrong with cpaymentconfirm")
	}
}
func (c *Redeemer) cpaymentSource() error {
	type BillingAddress struct {
		Name       string `json:"name"`
		Line1      string `json:"line_1"`
		Line2      string `json:"line_2"`
		City       string `json:"city"`
		State      string `json:"state"`
		PostalCode string `json:"postal_code"`
		Country    string `json:"country"`
		Email      string `json:"email"`
	}
	type Payload struct {
		PaymentGateway      int            `json:"payment_gateway"`
		Token               string         `json:"token"`
		BillingAddress      BillingAddress `json:"billing_address"`
		BillingAddressToken string         `json:"billing_address_token"`
	}
	payload := Payload{
		PaymentGateway: 1,
		Token:          c.PaymentMethod,
		BillingAddress: BillingAddress{
			Name:       "Null UwU",
			Line1:      "Delhi",
			Line2:      "Delhi",
			City:       "Delhi",
			State:      "Delhi",
			PostalCode: "10001",
			Country:    "KR",
			Email:      "",
		},
		BillingAddressToken: c.AddressToken,
	}
	paybody, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req := fasthttp.AcquireRequest()
	req.Header.SetRequestURIBytes([]byte(`https://discord.com/api/v9/users/@me/billing/payment-sources`))
	req.Header.SetMethod(fasthttp.MethodPost)
	req.Header.Set(`Accept`, `*/*`)
	req.Header.Set(`Accept-Encoding`, `br`)
	req.Header.Set(`Accept-Language`, `en-GB,en-US;q=0.9,en;q=0.8`)
	req.Header.Set(`Authorization`, c.Token)
	req.Header.Set(`Content-Type`, `application/json`)
	req.Header.Set(`Cookie`, c.Cookies)
	req.Header.Set(`Origin`, `https://discord.com`)
	req.Header.Set(`Referer`, `https://discord.com/channels/@me`)
	req.Header.Set(`Sec-Ch-Ua`, `Not/A)Brand";v="99", "Google Chrome";v="115", "Chromium";v="115`)
	req.Header.Set(`Sec-Ch-Ua-Mobile`, `?1`)
	req.Header.Set(`Sec-Ch-Ua-Platform`, `"Windows"`)
	req.Header.Set(`Sec-Fetch-Dest`, `empty`)
	req.Header.Set(`Sec-Fetch-Mode`, `cors`)
	req.Header.Set(`sec-fetch-site`, `same-origin`)
	req.Header.Set(`User-Agent`, c.Useragent)
	req.Header.Set(`X-Debug-Options`, `bugReporterEnabled`)
	req.Header.Set(`X-Discord-Locale`, `en-US`)
	req.Header.Set(`X-Discord-Timezone`, `Asia/Calcutta`)
	req.Header.Set(`x-context-properties`, `eyJsb2NhdGlvbiI6Ii9jaGFubmVscy9AbWUifQ==`)
	req.Header.Set(`X-Super-Properties`, c.Superproperties)
	req.Header.Set(`fingerprint`, c.Fingerprint)
	req.SetBodyRaw(paybody)
	resp := fasthttp.AcquireResponse()
	for {
		printProgress("[+] Adding Card!")
		err := c.Client.Do(req, resp)
		if err != nil {
			printNetworkError(0, "CPaymentSource", err.Error())
			printProgress("Retrying...")
			continue
		}
		break
	}
	if resp.StatusCode() == 200 {
		body, err := resp.BodyUnbrotli()
		if err != nil {
			return err
		}
		var card struct {
			CardId string `json:"id"`
		}
		err = json.Unmarshal(body, &card)
		if err != nil {
			return err
		}
		c.CardId = card.CardId
		printProgress("[*] CardId: " + c.CardId)
		printProgress("[*] Added Card! ")
		return nil
	} else {
		printNetworkError(resp.StatusCode(), fmt.Sprintf("CPaymentSource -> xxxxxx%s", c.Vccnum[6:]), string(resp.Body()))
		failedvcc <- fmt.Sprintf("%s:%s%s:%s", c.Vccnum, c.Expmonth, c.Expyear, c.Vcccvv)
		return errors.New("something went wrong with cpaymentSource")
	}
}

func (c *Redeemer) Redeem() error {
	req := fasthttp.AcquireRequest()
	req.SetRequestURIBytes([]byte(`https://discord.com/api/v9/entitlements/gift-codes/` + c.Promo + `/redeem`))
	req.Header.SetMethod(fasthttp.MethodPost)
	req.Header.Set(`Accept`, `*/*`)
	req.Header.Set(`Accept-Encoding`, `br`)
	req.Header.Set(`Accept-Language`, `en-GB,en-US;q=0.9,en;q=0.8`)
	req.Header.Set(`Authorization`, c.Token)
	req.Header.Set(`Content-Type`, `application/json`)
	req.Header.Set(`Cookie`, c.Cookies)
	req.Header.Set(`Origin`, `https://discord.com`)
	req.Header.Set(`Referer`, `https://discord.com/billing/promotions/`+c.Promo)
	req.Header.Set(`Sec-Ch-Ua`, `Not/A)Brand";v="99", "Google Chrome";v="115", "Chromium";v="115`)
	req.Header.Set(`Sec-Ch-Ua-Mobile`, `?1`)
	req.Header.Set(`Sec-Ch-Ua-Platform`, `"Windows"`)
	req.Header.Set(`Sec-Fetch-Dest`, `empty`)
	req.Header.Set(`Sec-Fetch-Mode`, `cors`)
	req.Header.Set(`sec-fetch-site`, `same-origin`)
	req.Header.Set(`User-Agent`, c.Useragent)
	req.Header.Set(`X-Debug-Options`, `bugReporterEnabled`)
	req.Header.Set(`X-Discord-Locale`, `en-US`)
	req.Header.Set(`X-Discord-Timezone`, `Asia/Calcutta`)
	req.Header.Set(`x-context-properties`, `eyJsb2NhdGlvbiI6Ii9jaGFubmVscy9AbWUifQ==`)
	req.Header.Set(`X-Super-Properties`, c.Superproperties)
	req.Header.Set(`fingerprint`, c.Fingerprint)
	req.SetBodyRaw([]byte(`{"channel_id":null,"payment_source_id":"` + c.CardId + `"}`))
	resp := fasthttp.AcquireResponse()
	for {
		printProgress("[+] Redeeming Promo")
		err := c.Client.Do(req, resp)
		if err != nil {
			printNetworkError(0, "Redeem", err.Error())
			printProgress("Retrying...")
			continue
		}
		break
	}
	if resp.StatusCode() == 200 {
		claimedtokens <- c.TokenFull
		return nil
	} else if strings.Contains(string(resp.Body()), "This gift has been redeemed already.") {
		failedpromo <- c.TokenFull
		return errors.New("gift code has already been redeemed :(")
	} else if strings.Contains(string(resp.Body()), "This payment method cannot be used") {
		failedvcc <- fmt.Sprintf("%s:%s%s:%s", c.Vccnum, c.Expmonth, c.Expyear, c.Vcccvv)
		return errors.New("card error gift can't be redeemed")
	} else if strings.Contains(string(resp.Body()), "Authentication required") {
		var stripe_payment_id struct {
			StripePaymentId string `json:"payment_id"`
		}
		err := json.Unmarshal(resp.Body(), &stripe_payment_id)
		if err != nil {
			return err
		}
		c.StripePaymentId = stripe_payment_id.StripePaymentId
		printProgress("[*] StripePaymentId: " + c.StripePaymentId)
		return errors.New("authentication required")
	} else {
		printNetworkError(resp.StatusCode(), fmt.Sprintf("Redeem -> xxxxxx%s", c.Vccnum[6:]), string(resp.Body()))
		failedvcc <- fmt.Sprintf("%s:%s%s:%s", c.Vccnum, c.Expmonth, c.Expyear, c.Vcccvv)
		return errors.New("something went wrong with redeem")
	}
}

func (c *Redeemer) cpaymentIntents() error {
	req := fasthttp.AcquireRequest()
	req.SetRequestURIBytes([]byte(`https://discord.com/api/v9/users/@me/billing/stripe/payment-intents/payments/` + c.StripePaymentId))
	req.Header.SetMethod(fasthttp.MethodGet)
	req.Header.Set(`Accept`, `*/*`)
	req.Header.Set(`Accept-Encoding`, `br`)
	req.Header.Set(`Accept-Language`, `en-GB,en-US;q=0.9,en;q=0.8`)
	req.Header.Set(`Authorization`, c.Token)
	req.Header.Set(`Content-Type`, `application/json`)
	req.Header.Set(`Cookie`, c.Cookies)
	req.Header.Set(`Origin`, `https://discord.com`)
	req.Header.Set(`Referer`, `https://discord.com/channels/@me`)
	req.Header.Set(`Sec-Ch-Ua`, `Not/A)Brand";v="99", "Google Chrome";v="115", "Chromium";v="115`)
	req.Header.Set(`Sec-Ch-Ua-Mobile`, `?1`)
	req.Header.Set(`Sec-Ch-Ua-Platform`, `"Windows"`)
	req.Header.Set(`Sec-Fetch-Dest`, `empty`)
	req.Header.Set(`Sec-Fetch-Mode`, `cors`)
	req.Header.Set(`sec-fetch-site`, `same-origin`)
	req.Header.Set(`User-Agent`, c.Useragent)
	req.Header.Set(`X-Debug-Options`, `bugReporterEnabled`)
	req.Header.Set(`X-Discord-Locale`, `en-US`)
	req.Header.Set(`X-Discord-Timezone`, `Asia/Calcutta`)
	req.Header.Set(`x-context-properties`, `eyJsb2NhdGlvbiI6Ii9jaGFubmVscy9AbWUifQ==`)
	req.Header.Set(`X-Super-Properties`, c.Superproperties)
	req.Header.Set(`fingerprint`, c.Fingerprint)
	resp := fasthttp.AcquireResponse()
	for {
		printProgress("[+] Getting PaymentIntents")
		err := c.Client.Do(req, resp)
		if err != nil {
			printNetworkError(0, "CPaymentIntent", err.Error())
			printProgress("Retrying...")
			continue
		}
		break
	}
	if resp.StatusCode() == 200 {
		body, err := resp.BodyUnbrotli()
		if err != nil {
			return err
		}
		var paymentIntents struct {
			Stripe_intent_Id string `json:"stripe_payment_intent_client_secret"`
		}
		err = json.Unmarshal(body, &paymentIntents)
		if err != nil {
			return err
		}
		c.StripeIntentId = paymentIntents.Stripe_intent_Id
		c.DispatchedStripeIntentId = strings.Split(paymentIntents.Stripe_intent_Id, "_secret_")[0]
		printProgress("[*] StripeIntentId: " + c.StripeIntentId)
		printProgress("[*] DispatchedStripeIntentID: " + c.DispatchedStripeIntentId)
		return nil
	} else {
		printNetworkError(resp.StatusCode(), fmt.Sprintf("CPaymentIntents -> xxxxxx%s", c.Vccnum[6:]), string(resp.Body()))
		failedvcc <- fmt.Sprintf("%s:%s%s:%s", c.Vccnum, c.Expmonth, c.Expyear, c.Vcccvv)
		return errors.New("something went wrong with cpaymentintents")
	}
}

func (c *Redeemer) cpaymentIntentsConfirm() error {
	req := fasthttp.AcquireRequest()
	req.SetRequestURIBytes([]byte(`https://api.stripe.com/v1/payment_intents/` + c.DispatchedStripeIntentId + `/confirm`))
	req.Header.SetMethod(fasthttp.MethodPost)
	req.Header.Set("authority", "api.stripe.com")
	req.Header.Set("accept", "application/json")
	req.Header.Set("accept-language", "en-US,en;q=0.9")
	req.Header.Set("content-type", "application/x-www-form-urlencoded")
	req.Header.Set("origin", "https://js.stripe.com")
	req.Header.Set("referer", "https://js.stripe.com/")
	req.Header.Set("sec-ch-ua", `"Not?A_Brand";v="8", "Chromium";v="108"`)
	req.Header.Set("sec-ch-ua-mobile", "?0")
	req.Header.Set("sec-ch-ua-platform", `"Windows"`)
	req.Header.Set("sec-fetch-dest", "empty")
	req.Header.Set("sec-fetch-mode", "cors")
	req.Header.Set("sec-fetch-site", "same-site")
	req.Header.Set("user-agent", c.Useragent)
	req.SetBodyRaw([]byte(`expected_payment_method_type=card&use_stripe_sdk=true&key=pk_live_CUQtlpQUF0vufWpnpUmQvcdi&client_secret=` + c.StripeIntentId))
	resp := fasthttp.AcquireResponse()
	for {
		printProgress("[+] PaymentIntentsConfrim")
		err := c.Client.Do(req, resp)
		if err != nil {
			printNetworkError(0, "CPaymentsConfirm", err.Error())
			printProgress("Retrying...")
			continue
		}
		break
	}
	if resp.StatusCode() == 200 || resp.StatusCode() == 201 || resp.StatusCode() == 204 {
		var PaymentIntentsConfirm struct {
			NextAction struct {
				UseStripeSdk struct {
					ThreeDSecure2Source string `json:"three_d_secure_2_source"`
					TransactionID       string `json:"server_transaction_id"`
				} `json:"use_stripe_sdk"`
			} `json:"next_action"`
		}
		err := json.Unmarshal(resp.Body(), &PaymentIntentsConfirm)
		if err != nil {
			return err
		}
		c.ThreeDSecure2Source = PaymentIntentsConfirm.NextAction.UseStripeSdk.ThreeDSecure2Source
		c.TransactionID = PaymentIntentsConfirm.NextAction.UseStripeSdk.TransactionID
		printProgress("[*] ThreeDSecure2Source: " + c.ThreeDSecure2Source)
		printProgress("[*] TransactionID: " + c.TransactionID)
		return nil
	} else {
		printNetworkError(resp.StatusCode(), fmt.Sprintf("CPaymentIntentsConfirm -> xxxxxx%s", c.Vccnum[6:]), string(resp.Body()))
		failedvcc <- fmt.Sprintf("%s:%s%s:%s", c.Vccnum, c.Expmonth, c.Expyear, c.Vcccvv)
		return errors.New("something went wrong with Cpaymentintentsconfirm")
	}
}

func (c *Redeemer) cThreeDsConfirm() error {
	data := url.Values{
		"source":                                 []string{c.ThreeDSecure2Source},
		"browser":                                []string{`{"fingerprintAttempted":true,"fingerprintData":"` + base64.StdEncoding.EncodeToString([]byte(`{"threeDSServerTransID":"`+c.TransactionID+`"}`)) + `","challengeWindowSize":null,"threeDSCompInd":"Y","browserJavaEnabled":false,"browserJavascriptEnabled":true,"browserLanguage":"en-US","browserColorDepth":"24","browserScreenHeight":"1080","browserScreenWidth":"1920","browserTZ":"240","browserUserAgent":"` + c.Useragent + `"}`},
		"one_click_authn_device_support[hosted]": []string{`false`},
		"one_click_authn_device_support[same_origin_frame]":                 []string{`false`},
		"one_click_authn_device_support[spc_eligible]":                      []string{`true`},
		"one_click_authn_device_support[webauthn_eligible]":                 []string{`true`},
		"one_click_authn_device_support[publickey_credentials_get_allowed]": []string{`true`},
		"key": []string{`pk_live_CUQtlpQUF0vufWpnpUmQvcdi`},
	}
	req := fasthttp.AcquireRequest()
	req.SetRequestURIBytes([]byte(`https://api.stripe.com/v1/3ds2/authenticate`))
	req.Header.SetMethod(fasthttp.MethodPost)
	req.Header.Set("authority", "api.stripe.com")
	req.Header.Set("accept", "application/json")
	req.Header.Set("accept-language", "en-US,en;q=0.9")
	req.Header.Set("cache-control", "no-cache")
	req.Header.Set("content-type", "application/x-www-form-urlencoded")
	req.Header.Set("origin", "https://js.stripe.com")
	req.Header.Set("pragma", "no-cache")
	req.Header.Set("referer", "https://js.stripe.com/")
	req.Header.Set("sec-ch-ua", `"Not.A/Brand";v="8", "Chromium";v="114", "Google Chrome";v="114"`)
	req.Header.Set("sec-ch-ua-mobile", "?0")
	req.Header.Set("sec-ch-ua-platform", `"Linux"`)
	req.Header.Set("sec-fetch-dest", "empty")
	req.Header.Set("sec-fetch-mode", "cors")
	req.Header.Set("sec-fetch-site", "same-site")
	req.Header.Set("user-agent", c.Useragent)
	req.SetBodyRaw([]byte(data.Encode()))
	resp := fasthttp.AcquireResponse()
	for {
		printProgress("[+] Getting ThreeDsConfirm")
		err := c.Client.Do(req, resp)
		if err != nil {
			printNetworkError(0, "CThreeDsConfrim", err.Error())
			printProgress("Retrying...")
			continue
		}
		break
	}
	if resp.StatusCode() == 200 {
		return nil
	} else {
		printNetworkError(resp.StatusCode(), fmt.Sprintf("CThreeDsConfirm -> xxxxxx%s", c.Vccnum[6:]), string(resp.Body()))
		failedvcc <- fmt.Sprintf("%s:%s%s:%s", c.Vccnum, c.Expmonth, c.Expyear, c.Vcccvv)
		return errors.New("something went wrong with CThreeDsConfirm")
	}
}

func (c *Redeemer) cBillingPayments() error {
	req := fasthttp.AcquireRequest()
	req.SetRequestURIBytes([]byte(`https://discord.com/api/v9/users/@me/billing/payments/` + c.StripePaymentId))
	req.Header.SetMethod(fasthttp.MethodGet)
	req.Header.Set(`Accept`, `*/*`)
	req.Header.Set(`Accept-Encoding`, `gzip, deflate, br`)
	req.Header.Set(`Accept-Language`, `en-GB,en-US;q=0.9,en;q=0.8`)
	req.Header.Set(`Authorization`, c.Token)
	req.Header.Set(`Content-Type`, `application/json`)
	req.Header.Set(`Cookie`, c.Cookies)
	req.Header.Set(`Origin`, `https://discord.com`)
	req.Header.Set(`Referer`, `https://discord.com/channels/@me`)
	req.Header.Set(`Sec-Ch-Ua`, `Not/A)Brand";v="99", "Google Chrome";v="115", "Chromium";v="115`)
	req.Header.Set(`Sec-Ch-Ua-Mobile`, `?1`)
	req.Header.Set(`Sec-Ch-Ua-Platform`, `"Windows"`)
	req.Header.Set(`Sec-Fetch-Dest`, `empty`)
	req.Header.Set(`Sec-Fetch-Mode`, `cors`)
	req.Header.Set(`sec-fetch-site`, `same-origin`)
	req.Header.Set(`User-Agent`, c.Useragent)
	req.Header.Set(`X-Debug-Options`, `bugReporterEnabled`)
	req.Header.Set(`X-Discord-Locale`, `en-US`)
	req.Header.Set(`X-Discord-Timezone`, `Asia/Calcutta`)
	req.Header.Set(`x-context-properties`, `eyJsb2NhdGlvbiI6Ii9jaGFubmVscy9AbWUifQ==`)
	req.Header.Set(`X-Super-Properties`, c.Superproperties)
	req.Header.Set(`fingerprint`, c.Fingerprint)
	resp := fasthttp.AcquireResponse()
	for {
		printProgress("[+] Getting cBillingPayments")
		err := c.Client.Do(req, resp)
		if err != nil {
			printNetworkError(0, "CBillingPayments", err.Error())
			printProgress("Retrying....")
			continue
		}
		break
	}
	if resp.StatusCode() == 200 {
		return nil
	} else {
		printNetworkError(resp.StatusCode(), fmt.Sprintf("CBillingPayments -> xxxxxx%s", c.Vccnum[6:]), string(resp.Body()))
		failedvcc <- fmt.Sprintf("%s:%s%s:%s", c.Vccnum, c.Expmonth, c.Expyear, c.Vcccvv)
		return errors.New("something went wrong with CBillingPayments")
	}
}

func readFile(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	proxies := []string{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		proxy := strings.TrimSpace(scanner.Text())
		if proxy != "" {
			proxies = append(proxies, proxy)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return proxies, nil
}
func writeToFile(filename string, contentCh <-chan string) {
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0666)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	for content := range contentCh {
		if _, err := io.WriteString(file, content+"\n"); err != nil {
			log.Printf("Error writing to file: %v\n", err)
		}
	}
}

func RemoveIndex(slice *[]string) {
	if len(*slice) == 0 {
		return
	}
	*slice = (*slice)[1:]
}

type Config struct {
	Threads      int  `json:"Threads"`
	Vccuse       int  `json:"Vccuse"`
	Proxy        bool `json:"Proxy"`
	NetworkDebug bool `json:"NetworkDebug"`
	ErrorPrint   bool `json:"ErrorPrint"`
	ProcessDebug bool `json:"ProcessDebug"`
}

var config Config
var (
	modkernel32         = syscall.NewLazyDLL("kernel32.dll")
	procSetConsoleTitle = modkernel32.NewProc("SetConsoleTitleW")
)

func setConsoleTitle(title string) {
	titlePtr, _ := syscall.UTF16PtrFromString(title)
	_, _, _ = procSetConsoleTitle.Call(uintptr(unsafe.Pointer(titlePtr)))
}

func main() {
	var wg sync.WaitGroup
	configFile, err := os.ReadFile("config.json")
	if err != nil {
		printError(0, "FILE", "Error while reading config.json")
		return
	}
	if err := json.Unmarshal(configFile, &config); err != nil {
		printError(0, "FILE", "Error while reading config.json")
		return
	}
	vccLines, err := readFile("Input/vccs.txt")
	if err != nil {
		printError(0, "FILE", "Error while reading vccs.txt")
		return
	}
	tokenLines, err := readFile("Input/tokens.txt")
	if err != nil {
		printError(0, "FILE", "Error while reading tokens.txt")
		return
	}
	promoLines, err := readFile("Input/promos.txt")
	if err != nil {
		printError(0, "FILE", "Error while reading promos.txt")
		return
	}
	proxyLines, err := readFile("Input/proxies.txt")
	if err != nil {
		printError(0, "FILE", "Error while reading proxies.txt")
		return
	}
	fmt.Print("\033[H\033[2J")
	banner(len(tokenLines), len(promoLines), len(vccLines), 0)
	if config.Proxy {
		fmt.Println("\033[38;5;178m[\033[0m\033[38;5;27mProxy\033[0m\033[38;5;178m]\033[0m: \033[0m \033[38;5;83mTrue\033[0m")
	} else {
		fmt.Println("\033[38;5;178m[\033[0m\033[38;5;27mProxy\033[0m\033[38;5;178m]\033[0m: \033[0m \033[38;5;161mFalse\033[0m")
	}
	limiter := make(chan struct{}, config.Threads)
	duplicatedvcc := []string{}
	for cc := range vccLines {
		for i := 0; i < config.Vccuse; i++ {
			duplicatedvcc = append(duplicatedvcc, vccLines[cc])
		}
	}
	go func() {
		started := time.Now()
		for {
			title := fmt.Sprintf("[THUNDER REDEEMER] │ Redeemed: %d │ Token %d │ VCC: %d │ Errors: %d │  Elapsed: %f", claimedint, len(tokenLines), len(vccLines), failed, time.Since(started).Seconds())
			setConsoleTitle(title)
		}
	}()
	go writeToFile("Output/claimed.txt", claimedtokens)
	go writeToFile("Output/failedtoken.txt", failedtokens)
	go writeToFile("Output/failedpromos.txt", failedpromo)
	go writeToFile("Output/failedvcc.txt", failedvcc)
	for len(duplicatedvcc) > 0 && len(tokenLines) > 0 && len(promoLines) > 0 {
		tokenfull := tokenLines[0]
		vcc := duplicatedvcc[0]
		promo := promoLines[0]
		limiter <- struct{}{}
		wg.Add(1)
		go func(tokenfull, vcc, promo string) {
			defer func() {
				<-limiter
				wg.Done()
			}()
			splitvcc := strings.Split(vcc, ":")
			client := Redeemer{
				Useragent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
				Token:     strings.Split(tokenfull, ":")[2],
				Vccnum:    splitvcc[0],
				Expmonth:  splitvcc[1][:2],
				Expyear:   splitvcc[1][2:],
				Vcccvv:    splitvcc[2],
				Muid:      uuid.NewString(),
				Guid:      uuid.NewString(),
				Sid:       uuid.NewString(),
				TokenFull: tokenfull,
			}
			if strings.Contains(promo, "https://discord.com/billing/") {
				client.Promo = strings.Split(promo, "s/")[1]
			} else if strings.Contains(promo, "https://promos.discord.gg/") {
				client.Promo = strings.Split(promo, "g/")[1]
			} else {
				printError(0, "PROMO FORMAT INVALID", "invalid promotion link format")
			}
			if config.Proxy {
				r := rand.New(rand.NewSource(time.Now().UnixNano()))
				client.Client = fasthttp.Client{
					Dial: fasthttpproxy.FasthttpHTTPDialer(proxyLines[r.Intn(len(proxyLines))]),
				}
			}
			err = client.superproperties()
			if err != nil {
				threadlock.Lock()
				failed++
				threadlock.Unlock()
				printError(0, "SuperProperties", err.Error())
				return
			}
			err = client.fingerprintncookies()
			if err != nil {
				threadlock.Lock()
				failed++
				threadlock.Unlock()
				printError(0, "FingerPrintCookies", err.Error())
				return
			}
			err = client.checktoken()
			if err != nil {
				threadlock.Lock()
				failed++
				threadlock.Unlock()
				printError(0, "CheckToken", err.Error())
				return
			}
			t := time.Now()
			err = client.ctokenize()
			if err != nil {
				threadlock.Lock()
				failed++
				threadlock.Unlock()
				printError(0, "CTokenize", err.Error())
				return
			}
			err = client.csetupintents()
			if err != nil {
				threadlock.Lock()
				failed++
				threadlock.Unlock()
				printError(0, "CSetupIntents", err.Error())
				return
			}
			err = client.validatebilling()
			if err != nil {
				threadlock.Lock()
				failed++
				threadlock.Unlock()
				printError(0, "ValidateBilling", err.Error())
				return
			}
			err = client.cpaymentConfirm()
			if err != nil {
				threadlock.Lock()
				failed++
				threadlock.Unlock()
				printError(0, "CPaymentConfirm", err.Error())
				return
			}
			err = client.cpaymentSource()
			if err != nil {
				threadlock.Lock()
				failed++
				threadlock.Unlock()
				printError(0, "CPaymentSource", err.Error())
				return
			}
			err = client.Redeem()
			if err != nil {
				if err.Error() == "authentication required" {
					er1 := client.cpaymentIntents()
					if er1 != nil {
						threadlock.Lock()
						failed++
						threadlock.Unlock()
						printError(0, "CPaymentIntents", er1.Error())
						return
					}
					er2 := client.cpaymentIntentsConfirm()
					if er2 != nil {
						threadlock.Lock()
						failed++
						threadlock.Unlock()
						printError(0, "CPaymentIntentsConfirm", er2.Error())
						return
					}
					er3 := client.cThreeDsConfirm()
					if er3 != nil {
						threadlock.Lock()
						failed++
						threadlock.Unlock()
						printError(0, "CThreeDsConfirm", er3.Error())
						return
					}
					time.Sleep(3 * time.Second)
					er4 := client.cBillingPayments()
					if er4 != nil {
						threadlock.Lock()
						failed++
						threadlock.Unlock()
						printError(0, "CBillingPayments", er4.Error())
						return
					}
					er5 := client.Redeem()
					if er5 != nil {
						threadlock.Lock()
						failed++
						threadlock.Unlock()
						printError(0, "Redeem", er5.Error())
						return
					}
					threadlock.Lock()
					claimedint++
					threadlock.Unlock()
					printClaimed(client.Token[:16], time.Since(t).Seconds())
				} else {
					threadlock.Lock()
					failed++
					threadlock.Unlock()
					printError(0, "Redeem", err.Error())
					return
				}
			}
		}(tokenfull, vcc, promo)
		RemoveIndex(&tokenLines)
		RemoveIndex(&promoLines)
		RemoveIndex(&duplicatedvcc)
	}
	wg.Wait()
	fmt.Printf("\n["+grey(time.Now().Format("15:04:05"))+"] \033[38;5;27mMaterials Remaining\033[0m \033[38;5;63m-->\033[0m \033[38;5;99mTOKENS:\033[0m \033[38;5;45m%d \033[0m \033[38;5;99mPROMO:\033[0m \033[38;5;45m%d \033[0m \033[38;5;99mDUPLICATEDVCC:\033[0m \033[38;5;45m%d \033[0m\n", len(tokenLines), len(promoLines), len(duplicatedvcc))
	s := make(chan os.Signal, 1)
	signal.Notify(s, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, os.Interrupt)
	<-s
}
func printClaimed(maskedToken string, elasped float64) {
	fmt.Printf("["+grey(time.Now().Format("15:04:05"))+"] \033[38;5;178m[\033[0m\033[38;5;13mClaimed\033[0m\033[38;5;178m]\033[0m: \033[38;5;119m%s**********\033[0m \033[38;5;178m[\033[0m\033[38;5;83m%f\033[0m\033[38;5;178m]\033[0m\n", maskedToken, elasped)
}
func printProgress(content string) {
	if config.ProcessDebug {
		fmt.Printf("["+grey(time.Now().Format("15:04:05"))+"] \033[38;5;83m%s\033[0m\n", content)
	}
}
func printError(stat int, header, msg string) {
	if config.ErrorPrint {
		fmt.Println("[" + grey(time.Now().Format("15:04:05")) + "] \033[38;5;178m[\033[0m\033[38;5;160m" + strconv.Itoa(stat) + "\033[0m\033[38;5;178m]\033[0m \033[38;5;178m[\033[0m\033[38;5;161m" + header + "\033[0m\033[38;5;178m]\033[0m: \033[38;5;196m" + msg + "\033[0m")
	}
}

func printNetworkError(stat int, header, msg string) {
	if config.NetworkDebug {
		fmt.Println("[" + grey(time.Now().Format("15:04:05")) + "] \033[38;5;178m[\033[0m\033[38;5;160m" + strconv.Itoa(stat) + "\033[0m\033[38;5;178m]\033[0m \033[38;5;178m[\033[0m\033[38;5;161m" + header + "\033[0m\033[38;5;178m]\033[0m: \033[38;5;196m" + msg + "\033[0m")
	}
}

func banner(token, promos, vcc, proxy int) {
	fmt.Print("\033[38;5;27m████████╗██╗  ██╗██╗   ██╗███╗   ██╗██████╗ ███████╗██████╗         ██████╗ ███████╗██████╗ ███████╗███████╗███╗   ███╗███████╗██████╗ \033[0m\n")
	fmt.Print("\033[38;5;63m╚══██╔══╝██║  ██║██║   ██║████╗  ██║██╔══██╗██╔════╝██╔══██╗        ██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝████╗ ████║██╔════╝██╔══██╗\033[0m\n")
	fmt.Print("\033[38;5;99m   ██║   ███████║██║   ██║██╔██╗ ██║██║  ██║█████╗  ██████╔╝        ██████╔╝█████╗  ██║  ██║█████╗  █████╗  ██╔████╔██║█████╗  ██████╔╝\033[0m\n")
	fmt.Print("\033[38;5;135m   ██║   ██╔══██║██║   ██║██║╚██╗██║██║  ██║██╔══╝  ██╔══██╗        ██╔══██╗██╔══╝  ██║  ██║██╔══╝  ██╔══╝  ██║╚██╔╝██║██╔══╝  ██╔══██╗\033[0m\n")
	fmt.Print("\033[38;5;171m   ██║   ██║  ██║╚██████╔╝██║ ╚████║██████╔╝███████╗██║  ██║        ██║  ██║███████╗██████╔╝███████╗███████╗██║ ╚═╝ ██║███████╗██║  ██║\033[0m\n")
	fmt.Print("\033[38;5;207m   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝  ╚═╝        ╚═╝  ╚═╝╚══════╝╚═════╝ ╚══════╝╚══════╝╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝\033[0m\n")
	fmt.Printf("\n\n\033[38;5;178m[\033[0m\033[38;5;141m-\033[0m\033[38;5;178m]\033[0m \033[38;5;207mTOKENS:\033[0m \033[38;5;45m%d \033[0m", token)
	fmt.Printf("\033[38;5;178m[\033[0m\033[38;5;141m-\033[0m\033[38;5;178m]\033[0m \033[38;5;207mPROMOS:\033[0m \033[38;5;45m%d \033[0m", promos)
	fmt.Printf("\033[38;5;178m[\033[0m\033[38;5;141m-\033[0m\033[38;5;178m]\033[0m \033[38;5;207mVCC:\033[0m \033[38;5;45m%d \033[0m", vcc)
	fmt.Printf("\033[38;5;178m[\033[0m\033[38;5;141m-\033[0m\033[38;5;178m]\033[0m \033[38;5;207mPROXIES:\033[0m \033[38;5;45m%d \033[0m\n\n", proxy)
}

func init() {
	console := windows.Stdout
	var consoleMode uint32
	windows.GetConsoleMode(console, &consoleMode)
	consoleMode |= windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING
	windows.SetConsoleMode(console, consoleMode)
}
