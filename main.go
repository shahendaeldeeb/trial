package main

import
(

	"net/http"
	"html/template"
	"encoding/json"
	"net/url"
	"strconv"
	"io/ioutil"
	"encoding/xml"
	"database/sql"
	_"github.com/go-sql-driver/mysql"
	"github.com/urfave/negroni"
   	gmux	"github.com/gorilla/mux"
	"github.com/goincremental/negroni-sessions"
	"github.com/goincremental/negroni-sessions/cookiestore"
	"fmt"
	"github.com/coopernurse/gorp"
	"golang.org/x/crypto/bcrypt"
)
type Book struct {
	PK int64	`db:"pk"`
	Title string	`db:"title"`
	Author string	`db:"author"`
	Classification string `db:"classification"`
	ID string      	`db:"id"`
	User string     `db:"user"`
}
type page struct {
	Books []Book
	Filter string
	 User string
}
type SearchResult struct {
	Title string     `xml:"title,attr"`
	Author string    `xml:"author,attr"`
	Year  string     `xml:"hyr,attr"`
	ID string        `xml:"owi,attr"`
}
type ClassifySearchResponse struct{

	//we use xml name tag to find the individual results of our search within each of the "work" parent node
	Results []SearchResult  `xml:"works>work"`
}
type ClassifyBookResponse struct{
	// it will be a nested struct to hold the right data from the xml file as follow
	BookData struct{
			 Title string     `xml:"title,attr"`
			 Author string    `xml:"author,attr"`
			 Year  string     `xml:"hyr,attr"`
			 ID string        `xml:"owi,attr"`
		 }`xml:"work"`
	Classification struct{
			 MostPopular string `xml:"sfa,attr"`
		 } `xml:"recommendations>ddc>mostPopular"`
}
type LoginPage struct {
	Error string
}
type User struct {
	Username string `db:"username"`
	Secret []byte   `db:"secret"`
}
var db *sql.DB
var dbmap *gorp.DbMap
func initDb(){

	db,_ =sql.Open("mysql" , "root:shahenda_hassan@/mydatabase")
	//first parameter is a pointer to our database , second is used sql (sqlight or mysql)
	dbmap = &gorp.DbMap{Db:db , Dialect:gorp.MySQLDialect{"InnoDB", "UTF8"}}
	// maps between go struct and database table
	dbmap.AddTableWithName(Book{} , "Books").SetKeys(true , "pk")
	// this time the primary key will not be incremented so we pass false here and set the primary key to username
	dbmap.AddTableWithName(User{} , "users").SetKeys(false , "username")
	dbmap.CreateTablesIfNotExists()
}
func verifyDatabase(w http.ResponseWriter , r *http.Request , next http.HandlerFunc){
	err := db.Ping();
	if err != nil{
		http.Error(w, err.Error() , http.StatusInternalServerError)
		return
	}
	//
	next(w,r)
}
func getBookCollection(books *[]Book , sortCol , filterByClass  ,username string, w http.ResponseWriter)bool{

	 if sortCol== "" {
		sortCol = "pk"
	 }
	  where := "where user=?"
	 if filterByClass == "fiction" {
		 where += "and classification between '800' and '900'"
	 }else if filterByClass =="nonfiction"{
		 where += "and classification not between '800' and '900'"
	 }
 	fmt.Println("sortcol" + sortCol)
	fmt.Println("username"+username)
	 _,err := dbmap.Select(books , "select * from Books " + where + " order by " + sortCol , username)
	 if err != nil {
		 http.Error(w,err.Error(),http.StatusInternalServerError)
		 return false
	 }
	 return true
 }
func getStringFromSession(r *http.Request , key string ) string{
	var strVal string
	if val:= sessions.GetSession(r).Get(key); val!= nil{
		strVal = val.(string)
	}
	return strVal
}
 // midlleware handler to verify that a user exists in the database with the username held in the session
func verifyUser (w http.ResponseWriter , r *http.Request , next http.HandlerFunc){
	if r.URL.Path == "/login" {
		next(w, r)
		return
	}
	// get value session key = User
	if username := getStringFromSession( r , "User") ; username != "" {
		// we will use it to query the database (check if user found )
		 if user , _ := dbmap.Get(User{} , username) ; user !=nil{
			 //we know that this user is valid
			 next(w,r)
			 return
		 }
	}
	http.Redirect(w , r, "/login" , http.StatusTemporaryRedirect)
}
func main() {

	initDb()
	mux := gmux.NewRouter()
	templates := template.Must(template.ParseFiles("index.html"))


	mux.HandleFunc("/login" , func(w http.ResponseWriter , r *http.Request) {
		var p LoginPage
		//create and store new users when the user clicks the register button
		fmt.Println(r.FormValue("register"))
		if r.FormValue("register") != ""{
			secret , _ := bcrypt.GenerateFromPassword([]byte(r.FormValue("password")) , bcrypt.DefaultCost)
			user :=User{r.FormValue("username") , secret}
			if err := dbmap.Insert(&user); err != nil{
				p.Error = err.Error()

			}else{
				//sessions.getsession() to create session variable
				//.set key-> User , value ->user.Username
				sessions.GetSession(r).Set("User" , user.Username)
				http.Redirect(w, r, "/" , http.StatusFound)
				return
			}


		}else if  r.FormValue("login") !=""{
			// here we use username as it is the primary key
			user , err := dbmap.Get(User{} , r.FormValue("username"))
			if err != nil {
				p.Error = err.Error()
				return
			}else if user == nil{
				p.Error = " No such user found with the username : " + r.FormValue("username")
			}else{
				u := user.(*User)
				err := bcrypt.CompareHashAndPassword(u.Secret , []byte(r.FormValue("password")))
				if err != nil{
					p.Error = err.Error()
				}else {
					sessions.GetSession(r).Set("User" , u.Username)
					http.Redirect(w, r, "/" , http.StatusFound)
					return
				}
			}
		 }
		template  := template.Must(template.ParseFiles("Login.html"))
		 if err:= template.Execute(w,p); err!= nil{
			 http.Error(w, err.Error() , http.StatusInternalServerError)
			 return
		 }
	})

	mux.HandleFunc( "/", func( w http.ResponseWriter, r *http.Request){

		p := page {Books:[]Book{} , Filter:getStringFromSession(r,"Filter") , User:getStringFromSession(r,"User")}

		if !getBookCollection(&p.Books ,getStringFromSession(r,"SortBy"),getStringFromSession(r,"Filter"),p.User, w){
			return
		}


		err := templates.ExecuteTemplate(w,"index.html",p)


		if err != nil {
			http.Error(w, err.Error(),http.StatusInternalServerError)
		}

	}).Methods("GET")

	mux.HandleFunc("/search" , func(w http.ResponseWriter , r *http.Request){
		var Results []SearchResult
		var err error

		Results,err = Search(r.FormValue("search"))

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}

		fmt.Println(Results)
		encoder := json.NewEncoder(w)
		err = encoder.Encode(Results)

		if err != nil{
			http.Error(w, err.Error() , http.StatusInternalServerError)
		}

	}).Methods("POST")

	mux.HandleFunc("/Books" , func(w http.ResponseWriter , r *http.Request){

		var book ClassifyBookResponse
		var err error
		book,err = find(r.FormValue("id"))
		if err != nil{
			http.Error(w,err.Error(),http.StatusInternalServerError)
		}



		// create new book object with the last inserted id
		// we inserted primary key = -1 as gorp will generate it once it has been inserted
		b := Book{
			PK:-1,
			Title:book.BookData.Title,
			Author:book.BookData.Author,
			Classification:book.Classification.MostPopular,
			ID:r.FormValue("id"),
			User:getStringFromSession(r,"User"),
		}

		if err = dbmap.Insert(&b); err!= nil{
			http.Error(w,err.Error(),http.StatusInternalServerError)
		}
		 // encode (convert to string )
		  err = json.NewEncoder(w).Encode(b)

		if err != nil{
			http.Error(w,err.Error(),http.StatusInternalServerError)
		}
		//defer db.Close()
	}).Methods("PUT")

	mux.HandleFunc("/books/{pk}", func(w http.ResponseWriter , r *http.Request) {
		pk , _ := strconv.ParseInt(gmux.Vars(r)["pk"] , 10 , 64)
		var b Book
		 if err := dbmap.SelectOne(&b , "select * from Books where pk=? and user=?" , pk , getStringFromSession(r,"User"));
		 err != nil{
			 http.Error(w, err.Error(), http.StatusInternalServerError)
		 }
		_, err := dbmap.Delete(&b)
		if err != nil{
			http.Error(w,err.Error(),http.StatusInternalServerError)
			return
		}
		// to tell the caller that everything is ok during the call
		w.WriteHeader(http.StatusOK)
	} ).Methods("DELETE")

	mux.HandleFunc("/books" , func(w http.ResponseWriter , r *http.Request) {
		 columnName := r.FormValue("sortBy")
		 var b [] Book

		if !getBookCollection(&b , columnName,getStringFromSession(r,"Filter"),getStringFromSession(r,"User"), w){
			return
		}
		// to get session for this request
		sessions.GetSession(r).Set("SortBy" , r.FormValue("sortBy"))
		err := json.NewEncoder(w).Encode(b)
		if err != nil {
			http.Error(w,err.Error(),http.StatusInternalServerError)
			return
		}
	}).Methods("GET").Queries("sortBy" , "{sortBy:title|author|classification}")
	mux.HandleFunc("/books" , func(w http.ResponseWriter , r *http.Request) {
		var b [] Book

		if !getBookCollection(&b , getStringFromSession(r,"sortBy"),r.FormValue("filter"),  getStringFromSession(r,"User") ,w){
			return
		}
		// to get session for this request
		sessions.GetSession(r).Set("Filter" , r.FormValue("filter"))
		err := json.NewEncoder(w).Encode(b)
		if err != nil {
			http.Error(w,err.Error(),http.StatusInternalServerError)
			return
		}
	}).Methods("GET").Queries("filter" , "{filter:all|fiction|nonfiction}")
	mux.HandleFunc("/logout" , func(w http.ResponseWriter , r *http.Request){
		sessions.GetSession(r).Set("User" , nil)
		sessions.GetSession(r).Set("Filter" , nil)
		sessions.GetSession(r).Set("SortBy" , nil)
		http.Redirect(w , r , "/login" , http.StatusFound)


	})

	//it provides some default middleware
	n := negroni.Classic()
	n.Use(sessions.Sessions("go-for-web-dev" , cookiestore.New([]byte("my-secret-123"))))
	//add Handler to middleware stack
	n.Use(negroni.HandlerFunc(verifyDatabase))
	n.Use(negroni.HandlerFunc(verifyUser))
	// to add http.Handler (process that runs in response to request made to web app.)alli f el mux in negroni stack
	n.UseHandler(mux)
	n.Run(":8085")
        defer db.Close()


}

func CheckError (err error){
	if err != nil{
		panic(err)
	}
}
func find(id string) (ClassifyBookResponse , error){
	var c ClassifyBookResponse
	body , err := classifyAPI("http://classify.oclc.org/classify2/Classify?&summary=true&owi=" + url.QueryEscape(id))

	if err != nil{
		return ClassifyBookResponse{} , err
	}
	// function convert from array of bytes to the type of the second parameter
	err = xml.Unmarshal(body,&c)
	return c , err
}
func Search(query string)([]SearchResult , error){

	body , err :=classifyAPI("http://classify.oclc.org/classify2/Classify?&summary=true&title=" + url.QueryEscape(query))
	fmt.Println(body)
	if err != nil {
		return []SearchResult{} , err
	}

	var c ClassifySearchResponse

	// it parse xml [] bytes code  to c object which is slice of SearchResult
	xml.Unmarshal(body , &c)
	return c.Results , err
}
// as we will use alot of code from search function we will put them in one func
func classifyAPI (url string)([]byte , error){
	// must create two variables ane for response and another for error
	var resp *http.Response
	var err error
	//http.get() request data from specific resource
	resp , err = http.Get(url)

	if err != nil{
		// return this error with empty results
		return  []byte{} , err
	}
	//to not cause memory leak
	defer resp.Body.Close()
	// to get data from response and it returns it in bytes
	return ioutil.ReadAll(resp.Body)
}