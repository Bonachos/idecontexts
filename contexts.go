package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/smtp"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/rs/cors"

	yaml "gopkg.in/yaml.v2"
)

const (
	httpListeningPort = "1333"
)

var (
	contextsFolder    = os.Getenv("CONTEXTSFOLDER")
	adminPassword     = os.Getenv("ADMINPASSWORD")
	jwtSecretToken    = os.Getenv("JWTSECRETTOKEN")
	geodataFolder     = os.Getenv("GEODATAFOLDER")
	annotationsFolder = os.Getenv("ANNOTATIONSFOLDER")
	errorsFolder      = os.Getenv("ERRORSFOLDER")
	emailServer       = os.Getenv("EMAILSERVER")
	emailPort         = os.Getenv("EMAILPORT")
	configFilePath    = os.Getenv("CONFIGFILEPATH")
	ideiaProfilingURL = "http://wssigdb.azores.gov.pt/IDEiAProfiling/IDEiAProfiling.svc"
	urlBO             = os.Getenv("URLBO")
	urlMapstore       = os.Getenv("URLMAPSTORE")
	userPassword      = os.Getenv("USERPASSWORD")
	jsonTokensMap     = make(map[string]string)
)

func main() {
	log.Println("+-------------------------------+")
	log.Println("|           Contexts            |")
	log.Println("+-------------------------------+")

	mux := http.NewServeMux()
	mux.HandleFunc("/context", context)
	mux.HandleFunc("/maps", mapsHandle)
	mux.HandleFunc("/login", loginHandle)
	mux.HandleFunc("/group", groupHandle)
	mux.HandleFunc("/user", userHandle)
	mux.HandleFunc("/annotation", annotationHandle)
	mux.HandleFunc("/geodata2geojson", geodata2geojson)
	mux.HandleFunc("/geodataupload", geodataupload)
	mux.HandleFunc("/wfsproxy", wfsproxy)
	mux.HandleFunc("/mapproxy", mapproxy)
	mux.HandleFunc("/proxy", proxy)
	mux.HandleFunc("/proxy/", proxy)
	mux.HandleFunc("/errorreport/", errorreport)

	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"http://localhost:8082", "http://localhost:1333"},
		AllowedHeaders:   []string{"Cache-Control"},
		AllowedMethods:   []string{http.MethodGet, http.MethodOptions, http.MethodPost, http.MethodPut, http.MethodDelete},
		AllowCredentials: true,
		// Debug: true,
	})

	// handler := cors.Default().Handler(mux)
	handler := c.Handler(mux)

	log.Println("Listening for connections on port: ", httpListeningPort)

	log.Fatal(http.ListenAndServe(":"+httpListeningPort, handler))

	log.Println("Bye!")
}

func context(w http.ResponseWriter, r *http.Request) {
	methodName := "context"
	var contextName string
	var entityName string
	var mapType string
	switch r.Method {
	case http.MethodGet:
		urlQuery := r.URL.Query()
		contextName = urlQuery.Get("c")
		entityName = urlQuery.Get("e")
		mapType = urlQuery.Get("t")
	default:
		http.Error(w, "Invalid request method.", http.StatusMethodNotAllowed)
		return
	}

	if contextName != "localConfig.json" {
		urlBOViewer := urlBO + "/viewer/" + entityName + "_-_" + contextName + "?view=default"
		client := &http.Client{}
		req, err := http.NewRequest("GET", urlBOViewer, nil)
		if err != nil {
			log.Println(methodName + ": " + err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		req.Header.Add("Authorization", jwtSecretToken)
		req.Header.Add("Accept", "application/json, text/plain, */*")
		req.Header.Add("Content-Type", "application/json;charset=UTF-8")
		resp, err := client.Do(req)
		if err != nil {
			log.Println(methodName + ": " + err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		respBody, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Println(methodName + ": " + err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		var viewerResult ViewerResult
		err = json.Unmarshal(respBody, &viewerResult)
		if err != nil {
			log.Println(methodName + ": " + err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if viewerResult.Inactive != nil && *viewerResult.Inactive {
			http.Error(w, "Inactive Viewer", http.StatusOK)
			return
		}

		if viewerResult.Anonymous != nil && !*viewerResult.Anonymous {
			authHeader := r.Header.Get("Authorization")
			authHeaderSplit := strings.Split(authHeader, " ")
			var requestUserName string
			if len(authHeaderSplit) > 1 {
				requestUserName = jsonTokensMap[authHeaderSplit[1]]
			}

			configuration := readConfig(configFilePath)

			requestUserIsAdmin := false
			for _, admin := range configuration.Admins {
				if admin.ID == requestUserName {
					requestUserIsAdmin = true
				}
			}

			if !requestUserIsAdmin {
				http.Error(w, "Not an Anonymous Viewer", http.StatusOK)
				return
			}
		}
	}

	getFilePath := filepath.Join(contextsFolder, entityName, contextName)
	if !strings.Contains(getFilePath, ".json") {
		getFilePath += ".json"
	}
	fileContent, err := ioutil.ReadFile(getFilePath)
	if err != nil {
		log.Println(methodName + ": " + err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if mapType == "cesium" {
		var mapConfig MapConfig
		err = json.Unmarshal(fileContent, &mapConfig)
		if err != nil {
			log.Println(methodName + ": " + err.Error())
			return
		}

		// TODO Calcular zoom a partir do MaxExtent
		mapConfig.Zoom = 3

		// TODO Min Zoom para Cesium para evitar distorções
		// mapConfig.MinZoom = 5
		// mapConfig.MaxZoom = 5
		mapConfig.MaxExtent = nil

		fileContent, err = json.Marshal(mapConfig)
		if err != nil {
			log.Println(methodName + ": " + err.Error())
			return
		}
	}
	_, err = w.Write(fileContent)
	if err != nil {
		log.Println(methodName + ": " + err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func mapsHandle(w http.ResponseWriter, r *http.Request) {
	methodName := "mapsHandle"
	switch r.Method {
	case http.MethodGet:
	default:
		http.Error(w, "Invalid request method.", http.StatusMethodNotAllowed)
	}

	urlBOViewers := urlBO + "/viewer?view=default"
	client := &http.Client{}
	req, err := http.NewRequest("GET", urlBOViewers, nil)
	if err != nil {
		log.Println(methodName + ": " + err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	req.Header.Add("Authorization", jwtSecretToken)
	req.Header.Add("Accept", "application/json, text/plain, */*")
	req.Header.Add("Content-Type", "application/json;charset=UTF-8")
	resp, err := client.Do(req)
	if err != nil {
		log.Println(methodName + ": " + err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Println(methodName + ": " + err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// log.Println(string(respBody))
	var viewerResults []ViewerResult
	err = json.Unmarshal(respBody, &viewerResults)
	if err != nil {
		log.Println(methodName + ": " + err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var results []Result
	for viewerNumber, viewerResult := range viewerResults {
		if viewerResult.Anonymous != nil && *viewerResult.Anonymous && (viewerResult.Inactive == nil || !*viewerResult.Inactive) {
			var viewerImage string
			if viewerResult.Image != nil {
				viewerImage = *viewerResult.Image
			}
			var viewerTitle string
			if viewerResult.Title != nil {
				viewerTitle = *viewerResult.Title
			}
			results = append(results, Result{
				CanDelete:   false,
				CanEdit:     false,
				CanCopy:     true,
				Creation:    "2020-06-08 09:00:00.123",
				LastUpdate:  "2020-06-08 09:00:00.234",
				Description: viewerTitle,
				ID:          strconv.Itoa(viewerNumber),
				Folder:      viewerResult.Folder,
				Entity:      viewerResult.Entity,
				Name:        viewerResult.Name,
				// Details:     "NODATA",
				Featured:  "false",
				Owner:     "admin",
				Thumbnail: viewerImage,
			})
		}

		// Currently LIMITING TO 8
		if len(results) == 8 {
			break
		}
	}

	mapsResult := &MapsResult{
		Success:    true,
		TotalCount: len(results),
		Results:    results,
	}

	mapsResultJSON, err := json.Marshal(mapsResult)
	if err != nil {
		log.Println(methodName + ": " + err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Add("content-type", "application/json")
	_, err = w.Write(mapsResultJSON)
	if err != nil {
		log.Println(methodName + ": " + err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func loginHandle(w http.ResponseWriter, r *http.Request) {
	methodName := "loginHandle"
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Println(methodName + ": " + err.Error())
		http.Error(w, "Login failed!", http.StatusUnauthorized)
	}

	userData := Login{}
	json.Unmarshal(body, &userData)

	username := userData.Email
	password := userData.Password
	log.Println("Username: " + userData.Email)
	jsonToken, err := login(username, password)
	if err != nil || jsonToken.Token == "" {
		log.Println(methodName + ": " + err.Error())
		http.Error(w, "Login failed!", http.StatusUnauthorized)
	}

	jsonTokensMap[jsonToken.Token] = username

	json, err := json.Marshal(jsonToken)
	if err != nil {
		log.Println(methodName + ": " + err.Error())
		http.Error(w, "Login failed!", http.StatusUnauthorized)
	}
	w.Write([]byte(json))
}

type UserGroups struct {
	ExtGroupList ExtGroupList `json:"ExtGroupList"`
}
type UserGroup struct {
	Description string `json:"description,omitempty"`
	Enabled     bool   `json:"enabled"`
	GroupName   string `json:"groupName"`
	ID          int    `json:"id"`
	Status      string `json:"status,omitempty"`
	Users       []User `json:"users,omitempty"`
	NewUsers    []User `json:"newUsers,omitempty"`
}
type ExtGroupList struct {
	GroupCount int         `json:"GroupCount"`
	Group      []UserGroup `json:"Group"`
}

type UserGroupDetails struct {
	UserGroup UserGroup `json:"UserGroup"`
}

func userAdminInGroup(requestUserName string, group GroupConfig, groups []GroupConfig) bool {
	if strings.Index(group.Name, " Admins") == len(group.Name)-len(" Admins") {
		for _, user := range *group.Users {
			if user.ID == requestUserName {
				return true
			}
		}
	}

	if strings.Index(group.Name, " Users") == len(group.Name)-len(" Users") {
		groupNameAdmins := group.Name[:len(group.Name)-len(" Users")] + " Admins"
		for _, group := range groups {
			if group.Name == groupNameAdmins {
				for _, user := range *group.Users {
					if user.ID == requestUserName {
						return true
					}
				}
			}
		}
	}
	return false
}

func groupHandle(w http.ResponseWriter, r *http.Request) {
	methodName := "groupHandle"
	switch r.Method {
	case http.MethodGet:
		authHeader := r.Header.Get("Authorization")
		authHeaderSplit := strings.Split(authHeader, " ")
		var requestUserName string
		if len(authHeaderSplit) > 1 {
			requestUserName = jsonTokensMap[authHeaderSplit[1]]
		}

		urlQuery := r.URL.Query()
		groupName := urlQuery.Get("g")
		configuration := readConfig(configFilePath)

		requestUserIsAdmin := false
		for _, admin := range configuration.Admins {
			if admin.ID == requestUserName {
				requestUserIsAdmin = true
			}
		}

		var userGroups UserGroups
		for _, group := range configuration.Groups {
			if requestUserIsAdmin || userAdminInGroup(requestUserName, group, configuration.Groups) {
				var users []User
				for _, user := range *group.Users {
					users = append(users, User{
						Name: user.ID,
					})
				}
				if groupName == "" || group.Name == groupName+" Admins" || group.Name == groupName+" Users" {
					userGroups.ExtGroupList.Group = append(userGroups.ExtGroupList.Group, UserGroup{
						Enabled:     group.Enabled,
						GroupName:   group.Name,
						Description: group.Description,
						Users:       users,
					})
				}
			}
		}
		userGroups.ExtGroupList.GroupCount = len(userGroups.ExtGroupList.Group)
		json, err := json.Marshal(userGroups)
		if err != nil {
			log.Println(methodName + ": " + err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_, err = w.Write(json)
		if err != nil {
			log.Println(methodName + ": " + err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	case http.MethodPost:
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			log.Printf("Error reading body: %v", err)
			http.Error(w, "can't read body", http.StatusBadRequest)
			return
		}
		// log.Println(string(body))
		var userGroupDetails UserGroupDetails
		json.Unmarshal(body, &userGroupDetails)

		configuration := readConfig(configFilePath)
		configuration.Groups = append(configuration.Groups, GroupConfig{
			Name:        userGroupDetails.UserGroup.GroupName,
			Description: userGroupDetails.UserGroup.Description,
			Enabled:     true,
			Users:       &[]UserConfig{},
		})
		writeConfig(configFilePath, configuration)
	case http.MethodPut:
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			log.Printf("Error reading body: %v", err)
			http.Error(w, "can't read body", http.StatusBadRequest)
			return
		}
		// log.Println(string(body))
		var userGroup UserGroup
		json.Unmarshal(body, &userGroup)

		configuration := readConfig(configFilePath)
		groupConfig := GroupConfig{
			Name:        userGroup.GroupName,
			Description: userGroup.Description,
			Enabled:     true,
			Users:       &[]UserConfig{},
		}
		for _, userAddGroup := range userGroup.NewUsers {
			*groupConfig.Users = append(*groupConfig.Users, UserConfig{
				ID: userAddGroup.Name,
			})
		}

		groupFound := false
		for _, group := range configuration.Groups {
			if group.Name == userGroup.GroupName {
				*group.Users = *groupConfig.Users
				groupFound = true
			}
		}

		if !groupFound {
			configuration.Groups = append(configuration.Groups, groupConfig)
		}

		writeConfig(configFilePath, configuration)
	default:
		http.Error(w, "Invalid request method.", http.StatusMethodNotAllowed)
	}

}

type Users struct {
	ExtUserList ExtUserList `json:"ExtUserList"`
}
type Groups struct {
	Group *[]UserGroup `json:"group"`
}
type User struct {
	Enabled bool   `json:"enabled"`
	Groups  Groups `json:"groups"`
	ID      int    `json:"id"`
	Name    string `json:"name"`
	Role    string `json:"role"`
}
type ExtUserList struct {
	UserCount int    `json:"UserCount"`
	User      []User `json:"User"`
}

func userHandle(w http.ResponseWriter, r *http.Request) {
	methodName := "userHandle"
	authHeader := r.Header.Get("Authorization")
	authHeaderSplit := strings.Split(authHeader, " ")
	var requestUserName string
	if len(authHeaderSplit) > 1 {
		requestUserName = jsonTokensMap[authHeaderSplit[1]]
	}

	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		urlQuery := r.URL.Query()
		userJSONToken := urlQuery.Get("j")
		userNameToGet := urlQuery.Get("u")
		if userJSONToken != "" {
			userNameToGet = jsonTokensMap[userJSONToken]
		}
		configuration := readConfig(configFilePath)

		if userNameToGet == "" {

			requestUserIsAdmin := false
			for _, admin := range configuration.Admins {
				if admin.ID == requestUserName {
					requestUserIsAdmin = true
				}
			}
			var users Users

			if requestUserIsAdmin {
				for _, user := range configuration.Admins {
					users.ExtUserList.User = append(users.ExtUserList.User, User{
						Enabled: true,
						Name:    user.ID,
						Role:    "ADMIN",
						Groups: Groups{
							Group: &[]UserGroup{},
						},
					})
				}

				for _, group := range configuration.Groups {
					for _, user := range *group.Users {
						groupAdd := UserGroup{
							Enabled:     group.Enabled,
							GroupName:   group.Name,
							Description: group.Description,
						}
						userAdd := User{
							Enabled: true,
							Name:    user.ID,
							Role:    "USER",
							Groups: Groups{
								Group: &[]UserGroup{groupAdd},
							},
						}

						userAdded := false
						for _, user := range users.ExtUserList.User {
							if user.Name == userAdd.Name {
								userAdded = true
								*user.Groups.Group = append(*user.Groups.Group, groupAdd)
								break
							}
						}
						if !userAdded {
							users.ExtUserList.User = append(users.ExtUserList.User, userAdd)
						}
					}
				}
			}

			users.ExtUserList.UserCount = len(users.ExtUserList.User)
			json, err := json.Marshal(users)
			if err != nil {
				log.Println(methodName + ": " + err.Error())
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			_, err = w.Write(json)
			if err != nil {
				log.Println(methodName + ": " + err.Error())
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			return
		}

		var usersMapStoreConfig UsersMapStoreConfig
		usersMapStoreConfig.User = UserMapStoreConfig{
			Enabled: true,
			Name:    userNameToGet,
			Role:    "USER",
			Groups: GroupsMapStoreConfig{
				Group: []GroupMapStoreConfig{},
			},
		}
		for _, user := range configuration.Admins {
			if user.ID == userNameToGet {
				usersMapStoreConfig.User.Role = "ADMIN"
			}
		}
		for _, group := range configuration.Groups {
			for _, user := range *group.Users {
				if user.ID == userNameToGet {
					usersMapStoreConfig.User.Groups.Group = append(usersMapStoreConfig.User.Groups.Group, GroupMapStoreConfig{
						Enabled:     true,
						GroupName:   group.Name,
						Description: group.Description,
					})
					break
				}
			}
		}

		json, err := json.Marshal(usersMapStoreConfig)
		if err != nil {
			log.Println(methodName + ": " + err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_, err = w.Write(json)
		if err != nil {
			log.Println(methodName + ": " + err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	case http.MethodPut:
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			log.Printf("Error reading body: %v", err)
			http.Error(w, "can't read body", http.StatusBadRequest)
			return
		}
		// log.Println(string(body))
		var user User
		json.Unmarshal(body, &user)

		configuration := readConfig(configFilePath)

		userFoundAsAdmin := -1
		for pos, admin := range configuration.Admins {
			if admin.ID == user.Name {
				userFoundAsAdmin = pos
			}
		}

		if user.Role == "ADMIN" && userFoundAsAdmin == -1 {
			configuration.Admins = append(configuration.Admins, &UserConfig{
				ID: user.Name,
			})
		} else if user.Role == "USER" && userFoundAsAdmin != -1 {
			configuration.Admins = removeUserFromAdmins(configuration.Admins, userFoundAsAdmin)
		}

		writeConfig(configFilePath, configuration)
	default:
		http.Error(w, "Invalid request method.", http.StatusMethodNotAllowed)
	}

}

func removeUserFromAdmins(c []*UserConfig, i int) []*UserConfig {
	c[len(c)-1], c[i] = c[i], c[len(c)-1]
	return c[:len(c)-1]
}

type UsersMapStoreConfig struct {
	User UserMapStoreConfig `json:"User"`
}
type GroupMapStoreConfig struct {
	Description string `json:"description,omitempty"`
	Enabled     bool   `json:"enabled"`
	GroupName   string `json:"groupName"`
	ID          int    `json:"id"`
}
type GroupsMapStoreConfig struct {
	Group []GroupMapStoreConfig `json:"group"`
}
type UserMapStoreConfig struct {
	Enabled bool                 `json:"enabled"`
	Groups  GroupsMapStoreConfig `json:"groups"`
	ID      int                  `json:"id"`
	Name    string               `json:"name"`
	Role    string               `json:"role"`
}

// A Config contains the configuration properties
type Config struct {
	Admins []*UserConfig `yaml:"admins,omitempty"`
	Groups []GroupConfig `yaml:"groups"`
}

// A GroupConfig contains the Users that belong to a GroupConfig
type GroupConfig struct {
	Name        string        `yaml:"name,omitempty" json:"name"`
	Description string        `yaml:"description,omitempty" json:"description"`
	Enabled     bool          `yaml:"enabled,omitempty" json:"enabled"`
	Users       *[]UserConfig `yaml:"users" json:"-"`
}

// A UserConfig contains user details
type UserConfig struct {
	ID string `yaml:"id,omitempty" json:"u"`
}

// ReadConfig reads a yaml configuration file and returns a Config
func readConfig(filename string) Config {
	config := Config{}
	configFile, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Println("Ocorreu um erro ao ler o ficheiro de configuração! Segue-se a informação detalhada do erro:")
		log.Panic(err.Error())
	}
	err = yaml.Unmarshal(configFile, &config)
	if err != nil {
		log.Println("Ocorreu um erro ao ler o ficheiro de configuração! Segue-se a informação detalhada do erro:")
		log.Panic(err.Error())
	}
	return config
}

// WriteConfig writes a yaml configuration file
func writeConfig(filename string, config Config) {
	configBytes, _ := yaml.Marshal(config)
	err := ioutil.WriteFile(filename, configBytes, os.ModePerm)
	if err != nil {
		log.Println("Ocorreu um erro ao escrever o ficheiro de configuração! Segue-se a informação detalhada do erro:")
	}
}

func login(username, password string) (jsonToken *JSONToken, errReturn error) {
	methodName := "login"
	var authenticationSuccessful bool
	if username == "admin" && password == adminPassword {
		authenticationSuccessful = true
	} else if username == "user" && password == userPassword {
		authenticationSuccessful = true
	} else if strings.Index(strings.ToLower(username), "@") > 0 {
		authenticationSuccessful = AuthenticateFBA(username, password)
	} else {
		if !strings.Contains(strings.ToUpper(username), "GRA\\") {
			username = "GRA\\" + username
		}
		var err error
		authenticationSuccessful, err = AuthenticateLDAP(username, password)
		if err != nil {
			return nil, err
		}
	}

	if authenticationSuccessful {
		claims := JWTData{
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: time.Now().Add(time.Hour * 24).Unix(),
			},

			CustomClaims: map[string]string{
				"userid": username,
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString([]byte(jwtSecretToken))
		if err != nil {
			log.Println(methodName + ": " + err.Error())
			return nil, err
		}

		jsonToken := &JSONToken{
			tokenString,
		}

		return jsonToken, nil
	}

	return
}

type JSONToken struct {
	Token string `json:"token"`
}

func geodata2geojson(w http.ResponseWriter, r *http.Request) {
	var fileName string
	switch r.Method {
	case http.MethodGet:
		urlQuery := r.URL.Query()
		fileName = urlQuery.Get("f")
	default:
		http.Error(w, "Invalid request method.", http.StatusMethodNotAllowed)
		return
	}

	stdoutStderr := convertgeodata2geojson(geodataFolder, fileName)

	// do something with output
	fmt.Printf("%s\n", stdoutStderr)
}

func convertgeodata2geojson(folder, fileName string) string {
	commandString := "docker run --rm -v " + folder + ":/tmp/data osgeo/gdal:alpine-small-3.2.1 ogr2ogr -f GeoJSON /tmp/data/" + fileName + ".geojson /tmp/data/" + fileName
	command := strings.Split(commandString, " ")
	if len(command) < 2 {
		log.Println("Parameters required")
		return ""
	}
	cmd := exec.Command(command[0], command[1:]...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		log.Println(err)
		log.Println(fmt.Sprint(err) + ": " + stderr.String())
	}
	stdoutStderr, err := cmd.CombinedOutput()
	if err != nil {
		log.Println(err)
		log.Println(fmt.Sprint(err) + ": " + stderr.String())
	}

	return string(stdoutStderr)
}

func annotationHandle(w http.ResponseWriter, r *http.Request) {
	methodName := "annotationHandle"
	switch r.Method {
	case http.MethodGet:
		urlQuery := r.URL.Query()
		annotationFileName := urlQuery.Get("a")

		annotationFilePath := filepath.Join(annotationsFolder, annotationFileName)
		if !strings.Contains(annotationFilePath, ".json") {
			annotationFilePath += ".json"
		}
		annotationFile, err := ioutil.ReadFile(annotationFilePath)
		if err != nil {
			log.Println(methodName + ": " + err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_, err = w.Write(annotationFile)
		if err != nil {
			log.Println(methodName + ": " + err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	case http.MethodPost:
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			log.Println(methodName + ": " + err.Error())
			http.Error(w, "No data or incorrect data in request!", http.StatusBadRequest)
		}

		annotationReport := AnnotationReport{}
		log.Println(string(body))
		err = json.Unmarshal(body, &annotationReport)
		if err != nil {
			log.Println(methodName + ": " + err.Error())
			http.Error(w, "Could not save annotation report!", http.StatusInternalServerError)
		}

		timeWithMicroSeconds := time.Now().Format("2006-01-02 15:04:05.000000")
		annotationFilename := filepath.Join(urlMapstore, "/contexts/annotation?a=annotation_"+timeWithMicroSeconds+".json")
		err = ioutil.WriteFile(annotationsFolder+annotationFilename, body, os.ModePerm)
		if err != nil {
			log.Println(methodName + ": " + err.Error())
			http.Error(w, "Could not save annotation report!", http.StatusInternalServerError)
		}

		notification := &notificationEmail{File: annotationFilename}

		emailConfig := &EMail{
			Server: emailServer,
			Port:   emailPort,
			From:   annotationReport.EmailAddress,
			To:     []string{annotationReport.EmailAddress},
		}
		sendNotificationMail(notification, *emailConfig)
	default:
		http.Error(w, "Invalid request method.", http.StatusMethodNotAllowed)
	}
}

func geodataupload(w http.ResponseWriter, r *http.Request) {
	log.Println("File Upload Endpoint Hit")

	// Parse our multipart form, 10 << 20 specifies a maximum
	// upload of 10 MB files.
	r.ParseMultipartForm(100 << 20)
	// FormFile returns the first file for the given key `myFile`
	// it also returns the FileHeader so we can get the Filename,
	// the Header and the size of the file
	file, handler, err := r.FormFile("file")
	if err != nil {
		log.Println("Error Retrieving the File")
		log.Println(err)
		return
	}
	defer file.Close()
	log.Printf("Uploaded File: %+v\n", handler.Filename)
	log.Printf("File Size: %+v\n", handler.Size)
	log.Printf("MIME Header: %+v\n", handler.Header)

	entity := r.FormValue("entity")

	fileBytes, err := ioutil.ReadAll(file)
	if err != nil {
		log.Println(err)
	}

	err = os.Mkdir(filepath.Join(geodataFolder, entity), 0755)
	if err != nil {
		log.Println(err)
	}

	err = ioutil.WriteFile(filepath.Join(geodataFolder, entity, handler.Filename), fileBytes, 0644)
	if err != nil {
		log.Println(err)
	}

	fileNameToConvert := filepath.Join(geodataFolder, entity, handler.Filename)
	if strings.Index(handler.Filename, ".json") == len(handler.Filename)-5 {
		err := os.Rename(fileNameToConvert, fileNameToConvert[:len(fileNameToConvert)-5]+".geojson")
		if err != nil {
			log.Println(err)
		}
	} else if strings.Index(handler.Filename, ".zip") == len(handler.Filename)-4 {
		fileNameWithoutExtension := handler.Filename[:len(handler.Filename)-4]
		unzipFolder := filepath.Join(geodataFolder, entity, fileNameWithoutExtension)
		err = os.Mkdir(unzipFolder, 0755)
		if err != nil {
			log.Println(err)
			return
		}
		_, err := Unzip(fileNameToConvert, unzipFolder)
		if err != nil {
			log.Println(err)
			return
		}
		convertgeodata2geojson(geodataFolder, filepath.Join(entity, fileNameWithoutExtension, fileNameWithoutExtension+".shp"))
		err = os.Rename(filepath.Join(unzipFolder, fileNameWithoutExtension+".shp.geojson"), filepath.Join(geodataFolder, entity, fileNameWithoutExtension+".geojson"))
		if err != nil {
			log.Println(err)
		}
	} else if strings.Index(handler.Filename, ".geojson") != len(handler.Filename)-8 {
		convertgeodata2geojson(geodataFolder, filepath.Join(entity, handler.Filename))
	}
	fmt.Fprintf(w, "Successfully Uploaded File\n")
}

func wfsproxy(w http.ResponseWriter, r *http.Request) {
	url, err := url.Parse(r.URL.String())
	if err != nil {
		log.Println(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	urlQuery := url.Query()
	urlQuery.Del("outputFormat")
	url.RawQuery = urlQuery.Encode()
	url.Scheme = "https"
	url.Host = "wssig5.azores.gov.pt"
	url.Path = "/idea/services/SIGENDA/COR/MapServer/WFSServer"

	client := &http.Client{}
	req, err := http.NewRequest("GET", url.String(), nil)
	if err != nil {
		log.Println(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Println(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Println(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	log.Println(string(respBody))
}

func mapproxy(w http.ResponseWriter, r *http.Request) {
	url, err := url.Parse(r.URL.String())
	if err != nil {
		log.Println(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	urlQuery := url.Query()
	styles := urlQuery.Get("STYLES")
	if styles == "" {
		urlQuery.Add("STYLES", "")
	}
	if styles == "<nil>" {
		urlQuery.Del("STYLES")
		urlQuery.Add("STYLES", "")
	}
	url.RawQuery = urlQuery.Encode()
	url.Scheme = "https"
	url.Host = "visualizador.idea.azores.gov.pt"
	url.Path = "/service"

	client := &http.Client{}
	req, err := http.NewRequest("GET", url.String(), nil)
	if err != nil {
		log.Println(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Println(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Println(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// log.Println(string(respBody))
	w.Write(respBody)
}

func proxy(w http.ResponseWriter, r *http.Request) {
	urlParsed, err := url.Parse(r.URL.String())
	if err != nil {
		log.Println(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	urlQuery := urlParsed.Query()
	urlFromURLQuery := urlQuery.Get("url")
	urlFromURLQueryUnescaped, err := url.QueryUnescape(urlFromURLQuery)
	if err != nil {
		log.Println(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	client := &http.Client{}
	req, err := http.NewRequest(r.Method, urlFromURLQueryUnescaped, r.Body)
	if err != nil {
		log.Println(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Println(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Println(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// log.Println(string(respBody))
	w.Write(respBody)
}

func errorreport(w http.ResponseWriter, r *http.Request) {
	methodName := "errorreport"
	switch r.Method {
	case http.MethodPost:
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			log.Println(methodName + ": " + err.Error())
			http.Error(w, "No data or incorrect data in request!", http.StatusBadRequest)
		}

		errorReport := ErrorReport{}
		log.Println(string(body))
		err = json.Unmarshal(body, &errorReport)
		if err != nil {
			log.Println(methodName + ": " + err.Error())
			http.Error(w, "Could not save error report!", http.StatusInternalServerError)
		}

		timeWithMicroSeconds := time.Now().Format("2006-01-02 15:04:05.000000")
		annotationFilename := filepath.Join(urlMapstore, "/contexts/errors/error?a=error_"+timeWithMicroSeconds+".json")
		err = ioutil.WriteFile(errorsFolder+annotationFilename, body, os.ModePerm)
		if err != nil {
			log.Println(methodName + ": " + err.Error())
			http.Error(w, "Could not save error report!", http.StatusInternalServerError)
		}
	default:
		http.Error(w, "Invalid request method.", http.StatusMethodNotAllowed)
	}
}

func Unzip(src string, dest string) ([]string, error) {

	var filenames []string

	r, err := zip.OpenReader(src)
	if err != nil {
		return filenames, err
	}
	defer r.Close()

	for _, f := range r.File {

		fpath := filepath.Join(dest, f.Name)

		if !strings.HasPrefix(fpath, filepath.Clean(dest)+string(os.PathSeparator)) {
			return filenames, fmt.Errorf("%s: illegal file path", fpath)
		}

		filenames = append(filenames, fpath)

		if f.FileInfo().IsDir() {
			os.MkdirAll(fpath, os.ModePerm)
			continue
		}

		if err = os.MkdirAll(filepath.Dir(fpath), os.ModePerm); err != nil {
			return filenames, err
		}

		outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return filenames, err
		}

		rc, err := f.Open()
		if err != nil {
			return filenames, err
		}

		_, err = io.Copy(outFile, rc)

		outFile.Close()
		rc.Close()

		if err != nil {
			return filenames, err
		}
	}
	return filenames, nil
}

type notificationEmail struct {
	Member string
	File   string
}

// An EMail contains the notification emails configuration properties
type EMail struct {
	Server string   `yaml:"server,omitempty"`
	Port   string   `yaml:"port,omitempty"`
	From   string   `yaml:"from,omitempty"`
	To     []string `yaml:"to,omitempty"`
}

func sendNotificationMail(notification *notificationEmail, emailConfig EMail) {
	configFile, err := ioutil.ReadFile("emails/notificationEmail.html")
	if err != nil {
		log.Println(err)
		return
	}

	tmpl := template.New("notificationEmail")
	tmpl, err = tmpl.Parse(string(configFile))
	if err != nil {
		log.Println("Parse: ", err)
		return
	}

	var bytesBuffer bytes.Buffer
	err1 := tmpl.Execute(&bytesBuffer, notification)
	if err1 != nil {
		log.Println("Execute: ", err1)
		return
	}
	notificationString := bytesBuffer.Bytes()
	log.Println(bytesBuffer.String())

	err = smtp.SendMail(emailConfig.Server+":"+emailConfig.Port, nil, emailConfig.From, emailConfig.To, notificationString)
	if err != nil {
		log.Println(err.Error())
	}
}

type MapsResult struct {
	Success    bool     `json:"success"`
	TotalCount int      `json:"totalCount"`
	Results    []Result `json:"results"`
}
type Result struct {
	CanDelete   bool   `json:"canDelete"`
	CanEdit     bool   `json:"canEdit"`
	CanCopy     bool   `json:"canCopy"`
	Creation    string `json:"creation"`
	LastUpdate  string `json:"lastUpdate"`
	Description string `json:"description"`
	ID          string `json:"id"`
	Name        string `json:"name"`
	Thumbnail   string `json:"thumbnail,omitempty"`
	Details     string `json:"details,omitempty"`
	Owner       string `json:"owner"`
	Featured    string `json:"featured,omitempty"`
	Entity      string `json:"entity,omitempty"`
	Folder      string `json:"folder,omitempty"`
}

// JWTData contains the JWT Claims
type JWTData struct {
	jwt.StandardClaims
	CustomClaims map[string]string `json:"custom,omitempty"`
}

// Login contains the parameters of a Login request
type Login struct {
	Email    string
	Password string
}

// AnnotationReport contains the features of an annotation report
type AnnotationReport struct {
	Features     []Features `json:"features"`
	MapName      string     `json:"mapName"`
	EmailAddress string     `json:"emailAddress,omitempty"`
}

// ErrorReport contains the information of an error report
type ErrorReport struct {
	Viewer       string `json:"viewer"`
	ErrorMessage string `json:"errorMessage"`
}

type Geometry struct {
	Coordinates []float64 `json:"coordinates,omitempty"`
	Type        string    `json:"type,omitempty"`
}
type Properties struct {
	ID             string `json:"id"`
	Title          string `json:"title"`
	IsValidFeature bool   `json:"isValidFeature"`
	CanEdit        bool   `json:"canEdit"`
}
type Style struct {
	IconGlyph string `json:"iconGlyph"`
	IconShape string `json:"iconShape"`
	IconColor string `json:"iconColor"`
	Highlight bool   `json:"highlight"`
	ID        string `json:"id"`
}
type Features struct {
	Type       string     `json:"type"`
	Geometry   Geometry   `json:"geometry,omitempty"`
	Properties Properties `json:"properties"`
	Features   []Features `json:"features"`
	Style      Style      `json:"style"`
}

// ViewerResult is the result type of the viewer service show method.
type ViewerResult struct {
	Name string
	// Title of viewer
	Title *string
	// Address (URL) of viewer
	URL *string
	// Image (thumbnail) URL of viewer
	Image *string
	// Folder that will define the URL of viewer
	Folder string
	// Hostname that can also be used to reference the viewer
	Hostname *string
	// X coordinate of the center of the viewer
	Centerx *string
	// Y coordinate of the center of the viewer
	Centery *string
	// CRS of the center of the viewer
	Centercrs *string
	// Public viewer (anonymous access)
	Anonymous *bool
	// Inactive viewer (in maintenance)
	Inactive *bool
	// CRS of the viewer
	Projection *string
	// Initial zoom of the viewer
	Zoom *string
	// Entity to which the viewer belongs
	Entity string
}
