package main

import (
	"crypto/md5"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/julienschmidt/httprouter"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path"
	"regexp"
	"strings"
	"sync"
	"time"
	"sync/atomic"
)

type FortuneDB struct {
	Filename      string
	Name          string
	FortuneBuf    string
	FortuneStarts []uint64
}

type Locator struct {
	Name string
	Id   uint64
}

type PermaLink struct {
	Links map[string]Locator
	Keys  []string
}

type FortuneCollection struct {
	DBs     map[string]*FortuneDB
	Links   *PermaLink
}

func (fdb *FortuneDB) Get(n uint64) (string, error) {
	if n > uint64(len(fdb.FortuneStarts)) {
		return "", fmt.Errorf("non-existent fortune")
	}
	start := fdb.FortuneStarts[n]
	var end uint64
	if n+1 >= uint64(len(fdb.FortuneStarts)) {
		end = uint64(len(fdb.FortuneBuf))
	} else {
		end = fdb.FortuneStarts[n+1] - 3
	}
	return fdb.FortuneBuf[start:end], nil
}

func (fdb *FortuneDB) Random() (string, error) {
	n := rand.Intn(len(fdb.FortuneStarts))
	f, err := fdb.Get(uint64(n))
	if err != nil {
		log.Printf("BUG: Looking up fdb->Random() failed %v", err)
	}
	return f, err
}

func (fc *FortuneCollection) Get(name string, n uint64) (string, error) {
	db, ok := fc.DBs[name]
	if !ok {
		return "", fmt.Errorf("not found")
	}
	return db.Get(n)
}

func (fc *FortuneCollection) Index() {
	start := time.Now()
	log.Println("Indexing..")
	index := make(map[string]Locator)
	keys := make([]string, 0)
	for name, fdb := range fc.DBs {
		for i := 0; i < len(fdb.FortuneStarts); i++ {
			fortune, err := fdb.Get(uint64(i))
			if err != nil {
				log.Printf("Failed to load %s:%d %v", name, i, err)
				continue
			}
			permname := fmt.Sprintf("%x", md5.Sum([]byte(fortune)))
			index[permname] = Locator{Name: name, Id: uint64(i)}
			keys = append(keys, permname)
		}
	}
	fc.Links = &PermaLink{
		Links: index,
		Keys:  keys,
	}
	log.Printf("Indexing done in %v (len(Links)=%d, len(keys)=%d", time.Now().Sub(start), len(fc.Links.Links), len(fc.Links.Keys))
}

func (fc *FortuneCollection) GetByPermalink(name string) (string, error) {
	if fc.Links == nil {
		return "", fmt.Errorf("no permalink index")
	}
	loc, ok := fc.Links.Links[name]
	if !ok {
		return "", fmt.Errorf("not found")
	}
	return fc.Get(loc.Name, loc.Id)
}

func (fc *FortuneCollection) BuildThresholds() {
	return
}

func (fc *FortuneCollection) UniformRandom() (string, error) {
	if fc.Links == nil {
		return "", fmt.Errorf("not ready")
	}
	nitems := len(fc.Links.Keys)
	key := fc.Links.Keys[rand.Intn(nitems)]
	return fc.GetByPermalink(key)
}

func (fc *FortuneCollection) ShittyRandom() (string, error) {
	keys := make([]string, len(fc.DBs))
	i := 0
	for k := range fc.DBs {
		keys[i] = k
		i++
	}
	return fc.DBs[keys[rand.Intn(len(keys))]].Random()

}

func (fc *FortuneCollection) Random() (string, error) {
	fortune, err := fc.UniformRandom()
	if err != nil {
		return fc.ShittyRandom()
	} else {
		return fortune, nil
	}
}

func (fc *FortuneCollection) Load(filename, name string) error {
	bytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}
	sbuf := string(bytes)
	r := regexp.MustCompile("(\n%\n|^%\n)")
	matches := r.FindAllStringIndex(sbuf, -1)
	indices := make([]uint64, len(matches))
	for i, n := range matches {
		indices[i] = uint64(n[1])
	}
	fc.DBs[name] = &FortuneDB{
		Filename:      filename,
		Name:          name,
		FortuneBuf:    sbuf,
		FortuneStarts: indices,
	}
	return nil
}

type Config struct {
	Filename string `json:"filename"`
	Name     string `json:"name"`
}

func fdbfromdir(dirname string) (*FortuneCollection, error) {
	finfo, err := ioutil.ReadDir(dirname)
	if err != nil {
		return nil, err
	}
	if len(finfo) == 0 {
		return nil, fmt.Errorf("no files found")
	}
	fdb := &FortuneCollection{
		DBs: make(map[string]*FortuneDB),
	}
	for _, fi := range finfo {
		filename := fmt.Sprintf("%s/%s", dirname, fi.Name())
		log.Printf("loading %s", filename)
		if err := fdb.Load(filename, fi.Name()); err != nil {
			log.Printf("Failed to load %s: %v", filename, err)
			return nil, err
		}
	}
	return fdb, nil
}

func logrequest(r *http.Request, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	log.Printf("%s %s %s %s [UA:%s]: %s", r.RemoteAddr, r.Method, r.Host, r.URL.Path, r.Header.Get("User-Agent"), msg)
}

func htmlifyfortune(fortune string, _ *http.Request, w http.ResponseWriter) {
	out := `<html>
	<head>
		<title>Fortunes!</title>
	</head>
	<body>
		<pre>
%s
		</pre>
		<a href="%s">permalink</a>
	</body>
</html>
`
	fmt.Fprintf(w, out, fortune, fmt.Sprintf("/permalink/%x", md5.Sum([]byte(fortune))))
}

type FortuneV0 struct {
	Fortune   string `json:"fortune"`
	PermaLink string `json:"permalink"`
}

func (f FortuneV0) Emit(w http.ResponseWriter) error {
	encoder := json.NewEncoder(w)
	return encoder.Encode(f)
}

func NewV0(fortune string) FortuneV0 {
	return FortuneV0{
		Fortune:   fortune,
		PermaLink: fmt.Sprintf("/api/v0/permalink/%x", md5.Sum([]byte(fortune))),
	}
}

type ShittyRender string

func (sr ShittyRender) Add(id string) error {
	if len(sr) == 0 {
		return fmt.Errorf("shitty render state tracking not enabled")
	}
	accept, err := regexp.Compile("^[a-fA-F0-9]{32}$")
	if err != nil {
		log.Printf("BUG: regexp doesn't compile for shittyrenders")
		return fmt.Errorf("regular expressions are hard")
	}
	if !accept.MatchString(id) {
		return fmt.Errorf("invalid id")
	}
	srfn := path.Join(string(sr), id)
	if fh, err := os.Create(srfn); err != nil {
		return err
	} else {
		fh.Close()
		return nil
	}
}

func (sr ShittyRender) List() ([]string, error) {
	finfo, err := ioutil.ReadDir(string(sr))
	if err != nil {
		return []string{}, err
	}
	dirs := make([]string, 0)
	for _, fi := range finfo {
		dirs = append(dirs, fi.Name())
	}
	return dirs, nil
}

func (sr ShittyRender) APIV0GETShittyRender(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	bad, err := sr.List()
	if err != nil {
		http.Error(w, "fail and wrong", http.StatusInternalServerError)
		logrequest(r, "Failed to get shitty renders %v", err)
		return
	}
	encoder := json.NewEncoder(w)
	if err := encoder.Encode(bad); err != nil {
		http.Error(w, "json encoding is difficult", http.StatusInternalServerError)
		logrequest(r, "Failed to encode %v as json %v", sr, err)
	}
}

func (sr ShittyRender) APIV0PUTShittyRender(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	if err := sr.Add(ps.ByName("id")); err != nil {
		log.Printf("Invalid shitty render request: %v", err)
		http.Error(w, "badness", http.StatusBadRequest)
		return
	}
	w.Write([]byte("OK\n"))
}

func (fc *FortuneCollection) GETApiV0DBS(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	dbs := make([]string, 0)
	for key := range fc.DBs {
		dbs = append(dbs, key)
	}
	encoder := json.NewEncoder(w)
	if err := encoder.Encode(dbs); err != nil {
		logrequest(r, "Failed to json encode dbs: %v", err)
		http.Error(w, "JSON encoding is difficult, soz", http.StatusInternalServerError)
		return
	}
}

func (fc *FortuneCollection) GETApiV0Random(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	fortune, err := fc.Random()
	if err != nil {
		http.Error(
			w,
			"Bad stuff happened, it's probably logged, and nobody will probably read that",
			http.StatusInternalServerError)
		logrequest(r, "fdb.Random() failed %v", err)
		return
	} else {
		rsp := NewV0(fortune)
		err := rsp.Emit(w)
		fid := fmt.Sprintf("%x", md5.Sum([]byte(fortune)))
		if err != nil {
			http.Error(w, "JSON encoding is really difficult, I'm sorry I failed you", http.StatusInternalServerError)
			logrequest(r, "Failed to JSON encode fortune %s: %v", fid, err)
			return
		}
	}
}

// "/api/v0/fortune/:db",
func (fc *FortuneCollection) GETApiV0RandomByDB(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	db, ok := fc.DBs[ps.ByName("db")]
	if !ok {
		http.NotFound(w, r)
		return
	}
	fortune, err := db.Random()
	if err != nil {
		http.Error(
			w,
			"Bad stuff happened, no soup for you",
			http.StatusInternalServerError)
		logrequest(r, "Failed to fetch fortune for %s: %v", ps.ByName("db"), err)
		return
	}
	if err = NewV0(fortune).Emit(w); err != nil {
		http.Error(w, "Making JSON is hard", http.StatusInternalServerError)
		logrequest(r, "Failed to emit json: %v", err)
		return
	}
}

func (fc *FortuneCollection) GETAPIV0PermalinkById(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	fid := ps.ByName("id")
	fortune, err := fc.GetByPermalink(fid)
	if err != nil {
		http.Error(w, "Failed to fetch your fortune", http.StatusInternalServerError)
		logrequest(r, "Failed to look up fortune %s: %v", fid, err)
		return
	}
	if err := NewV0(fortune).Emit(w); err != nil {
		logrequest(r, "Failed to emit fortune: %v", err)
		http.Error(w, "Failed to make your cookie", http.StatusInternalServerError)
		return
	}
}

func (fc *FortuneCollection) GETRandomFortune(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	start := time.Now()
	fortune, err := fc.Random()
	html := false
	if err != nil {
		http.Error(w, "Bad stuff happened", http.StatusInternalServerError)
		return
	} else {
		accept := strings.Split(r.Header.Get("Accept"), ",")
		for _, content := range accept {
			if content == "text/html" {
				html = true
				break
			}
		}
		permid := fmt.Sprintf("%x", md5.Sum([]byte(fortune)))
		w.Header().Add("X-Permalink", fmt.Sprintf("/permalink/%s", permid))
		if html {
			htmlifyfortune(fortune, r, w)
		} else {
			io.WriteString(w, fortune+"\n")
		}
	}
	logrequest(r, "served random with err=%v html=%v in %v", err, html, time.Now().Sub(start))
}

func (fc *FortuneCollection) GETRandomByDB(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	html := false
	db, ok := fc.DBs[ps.ByName("db")]
	if !ok {
		http.NotFound(w, r)
		return
	}
	fortune, err := db.Random()
	if err != nil {
		http.Error(w, "Fail and wrong", http.StatusInternalServerError)
	} else {
		accept := strings.Split(r.Header.Get("Accept"), ",")
		for _, content := range accept {
			if content == "text/html" {
				html = true
				break
			}
		}
		permid := fmt.Sprintf("%x", md5.Sum([]byte(fortune)))
		w.Header().Add("X-Permalink", fmt.Sprintf("/permalink/%s", permid))
		if html {
			htmlifyfortune(fortune, r, w)
		} else {
			io.WriteString(w, fortune+"\n")
		}
	}
	logrequest(r, "served random for %s err=%v", ps.ByName("db"), err)
}

func (fc *FortuneCollection) GETByPermalink(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	start := time.Now()
	fortune, err := fc.GetByPermalink(ps.ByName("id"))
	if err != nil {
		logrequest(r, "Failed to get by permalink %s: %v", ps.ByName("id"), err)
		http.Error(w, "Bad stuff happened", http.StatusInternalServerError)
	} else {
		io.WriteString(w, fortune)
	}
	logrequest(r, "served with err=%v in %v", err, time.Now().Sub(start))
}

type RequestFilter struct {
	VerboseLoggingUntil *int64
	VHost               *string
	Stats               *sync.Map
}

func (rf RequestFilter) DoStats(r *http.Request) {
	urlpath := r.URL.Path
	replace := regexp.MustCompile("/?[0-9a-fA-F]{32}$")
	stubbed := replace.ReplaceAllString(urlpath, "")
	newval := uint64(1)
	iptr, found := rf.Stats.LoadOrStore(stubbed, &newval)
	if found {
		if ptr, ok := iptr.(*uint64); ok {
			atomic.AddUint64(ptr, 1)
		} else {
			log.Printf("BUG: Updating stats, statvalue not *uint64 but %v", iptr)
		}
	}
}

func (rf RequestFilter) HandleStats(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	stats := make(map[string]uint64)
	rf.Stats.Range(func (key, value interface{}) bool {
		var skey string
		var ptr *uint64
		var ok bool
		if skey, ok = key.(string); !ok {
			log.Printf("Non-string stats key %v", key)
			return false
		}
		if ptr, ok = value.(*uint64); !ok {
			log.Printf("Non-*uint64 stats value %v", value)
			return false
		}
		stats[skey] = *ptr
		return true
	})
	err := json.NewEncoder(w).Encode(stats)
	if err != nil {
		http.Error(w,"Faff and wrong", http.StatusInternalServerError)
	}
}

func (rf RequestFilter) Filter(h func(w http.ResponseWriter, r *http.Request, ps httprouter.Params)) func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		stripport := regexp.MustCompile(":\\d+$")
		stripdot := regexp.MustCompile("\\.$")
		reqhost := stripdot.ReplaceAllString(stripport.ReplaceAllString(r.Host, ""), "")
		if r.ProtoMajor != 1 && r.ProtoMajor != 1 {
			logrequest(r, "Bad protocol UA %s", r.Header.Get("User-Agent"))
			http.Error(w, "Try http 1.1", http.StatusForbidden)
			return
		}
		if rf.VHost != nil && *rf.VHost != reqhost {
			logrequest(r, "Redirecting to %s", *rf.VHost)
			http.Redirect(w, r, fmt.Sprintf("http://%s/", *rf.VHost), http.StatusPermanentRedirect)
			return
		}
		rf.DoStats(r)
		start := time.Now()
		h(w, r, ps)
		if rf.VerboseLoggingUntil != nil && *rf.VerboseLoggingUntil < time.Now().Unix() {
			logrequest(r, "completed in %v", time.Now().Sub(start))
		}
	}
}

func HandleStaticFile(root string, w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	fn := ps.ByName("fn")
	if strings.HasSuffix(fn, ".css") || strings.HasSuffix(fn, ".html") || strings.HasSuffix(fn, ".js") {
		http.ServeFile(w, r, path.Join(root, fn))
	} else {
		http.NotFound(w, r)
	}
}

func main() {
	listen := flag.String("listen", ":8081", "Where to listen to")
	static := flag.String("static", "static", "static asset location")
	loaddir := flag.String("dir", "", "Fortune files to read (directory)")
	vhost := flag.String("vhost", "", "Only allow requests for host")
	failtoroot := flag.Bool("failtoroot", true, "Don't run as root")
	sr := flag.String("shittyrender", "", "Shitty render directory")
	flag.Parse()
	if os.Getuid() == 0 && *failtoroot {
		log.Printf("Refusing to run as root")
		return
	}
	var fdb *FortuneCollection
	var err error
	if len(*loaddir) > 0 {
		fdb, err = fdbfromdir(*loaddir)
	} else {
		err = fmt.Errorf("Must specify -ff or -dir")
	}
	if err != nil {
		log.Printf("Failed to load fortunefiles from: %v", err)
		return
	}
	rf := RequestFilter{
		VerboseLoggingUntil: nil,
		VHost:               vhost,
		Stats:               &sync.Map{},
	}
	shittyrender := ShittyRender(*sr)
	go fdb.Index()
	router := httprouter.New()
	router.GET("/api/v0/dbs", rf.Filter(fdb.GETApiV0DBS))
	router.GET("/api/v0/fortune", rf.Filter(fdb.GETApiV0Random))
	router.GET("/api/v0/fortune/:db", rf.Filter(fdb.GETApiV0RandomByDB))
	router.GET("/api/v0/permalink/:id", rf.Filter(fdb.GETAPIV0PermalinkById))
	router.GET("/api/v0/stats", rf.Filter(rf.HandleStats))
	router.GET("/static/:fn", rf.Filter(func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		HandleStaticFile(*static, w, r, ps)
	}))
	router.GET("/", rf.Filter(fdb.GETRandomFortune))
	router.GET("/db/:db", rf.Filter(fdb.GETRandomByDB))
	router.GET("/permalink/:id", rf.Filter(fdb.GETByPermalink))
	router.GET("/api/v0/shittyrender", rf.Filter(shittyrender.APIV0GETShittyRender))
	router.PUT("/api/v0/shittyrender/:id", rf.Filter(shittyrender.APIV0PUTShittyRender))
	srv := &http.Server{Addr: *listen, Handler: router}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	if ns := os.Getenv("NOTIFY_SOCKET"); len(ns) > 0 {
		log.Printf("notifying systemd")
		sock, err := net.Dial("unixgram", ns)
		if err != nil {
			log.Panicf("Failed to open NOTIFY_SOCKET=%s %v", ns, err)
		}
		_, err = sock.Write([]byte(fmt.Sprintf("MAIN_PID=%d\nREADY=1\n", os.Getpid())))
		if err != nil {
			log.Panicf("Failed to write to NOTIFY_SOCKET=%s %v", ns, err)
		}
	}
	err = srv.Serve(ln.(*net.TCPListener))
	if err != nil {
		log.Fatal(err)
	}
}
