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
	"os/user"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type FortuneDB struct {
	Filename      string
	Name          string
	FortuneBuf    string
	FortuneStarts []uint64
}

type DBThreshold struct {
	Threshold float64
	Key       string
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
	Weights []DBThreshold
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
	keys := []string{}
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
		return nil, fmt.Errorf("No files found")
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

func dropprivs() {

	u, err := user.Lookup("nobody")
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Dropping privileges %s:%s", u.Uid, u.Gid)
	uid, err := strconv.ParseInt(u.Uid, 10, 64)
	if err != nil {
		log.Fatal(err)
	}
	gid, err := strconv.ParseInt(u.Gid, 10, 64)
	if err != nil {
		log.Fatal(err)
	}
	if err := syscall.Setgroups([]int{}); err != nil {
		log.Fatalf("Failed to change user groups %v", err)
	}

	if err := syscall.Setgid(int(gid)); err != nil {
		log.Fatalf("Failed to change group: %v", err)
	}
	if err := syscall.Setuid(int(uid)); err != nil {
		log.Fatalf("Failed to change user: %v", err)
	}
}

func htmlifyfortune(fortune string, r *http.Request, w http.ResponseWriter) {
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

type FortuneStats struct {
	SuccessCounts *sync.Map
	FailCounts    *sync.Map
}

func (fs FortuneStats) Register(method, path string) (func(), func()) {
	failcount := uint64(0)
	successcount := uint64(0)
	key := fmt.Sprintf("%s %s", method, path)
	_, loaded := fs.SuccessCounts.LoadOrStore(key, &successcount)
	if loaded {
		log.Panicf("BUG: duplicate success stats for %s %s", method, path)
	}
	_, loaded = fs.FailCounts.LoadOrStore(key, &failcount)
	if loaded {
		log.Panicf("BUG: duplicate fail stats for %s %s", method, path)
	}
	succ := func() {
		atomic.AddUint64(&successcount, 1)
	}
	fail := func() {
		atomic.AddUint64(&failcount, 1)
	}
	return succ, fail
}

type StatsV0 struct {
	SuccessCounts map[string]uint64 `json:"success"`
	FailCounts    map[string]uint64 `json:"failures"`
}

func rangeinto(sm *sync.Map, out *map[string]uint64) error {
	var failed error
	sm.Range(func(key, value interface{}) bool {
		k, ok := key.(string)
		if !ok {
			log.Printf("failcounts non-string key %v", key)
			failed = fmt.Errorf("non-string key %v", key)
			return false
		}
		v, ok := value.(*uint64)
		if !ok {
			failed = fmt.Errorf("non-*uint64 value %v", value)
			log.Printf("failcounts non-*uint64 value %v", value)
			return false
		}
		(*out)[k] = *v
		return true
	})
	return failed
}

func (fs FortuneStats) JSON(w http.ResponseWriter) error {
	stats := StatsV0{
		SuccessCounts: make(map[string]uint64),
		FailCounts:    make(map[string]uint64),
	}
	if err := rangeinto(fs.FailCounts, &stats.FailCounts); err != nil {
		return fmt.Errorf("failed enumerating failcounts: %v", err)
	}
	if err := rangeinto(fs.SuccessCounts, &stats.SuccessCounts); err != nil {
		return fmt.Errorf("failed to enumerate successcounts: %v", err)
	}
	return json.NewEncoder(w).Encode(stats)
}

func main() {
	listen := flag.String("listen", ":8081", "Where to listen to")
	static := flag.String("static", "static", "static asset location")
	loaddir := flag.String("dir", "", "Fortune files to read (directory)")
	flag.Parse()
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
	fs := FortuneStats{
		SuccessCounts: &sync.Map{},
		FailCounts:    &sync.Map{},
	}
	go fdb.Index()
	router := httprouter.New()
	s_stats, f_stats := fs.Register("GET", "/api/v0/stats")
	router.GET("/api/v0/stats", func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		if err := fs.JSON(w); err != nil {
			f_stats()
			http.Error(w, "Failed to make up some stats", http.StatusInternalServerError)
			logrequest(r, "Failed to make stats %v", err)
		} else {
			s_stats()
		}
	})
	s_api_dbs, f_api_dbs := fs.Register("GET", "/api/v0/dbs")
	router.GET("/api/v0/dbs", func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		dbs := make([]string, 0)
		for key := range fdb.DBs {
			dbs = append(dbs, key)
		}
		encoder := json.NewEncoder(w)
		if err := encoder.Encode(dbs); err != nil {
			f_api_dbs()
			logrequest(r, "Failed to json encode dbs: %v", err)
			http.Error(w, "JSON encoding is difficult, soz", http.StatusInternalServerError)
			return
		}
		s_api_dbs()
	})
	s_api_rf, f_api_rf := fs.Register("GET", "/api/v0/fortune")
	router.GET("/api/v0/fortune", func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		fortune, err := fdb.Random()
		if err != nil {
			http.Error(
				w,
				"Bad stuff happened, it's probably logged, and nobody will probably read that",
				http.StatusInternalServerError)
			logrequest(r, "fdb.Random() failed %v", err)
			f_api_rf()
			return
		} else {
			rsp := NewV0(fortune)
			err := rsp.Emit(w)
			fid := fmt.Sprintf("%x", md5.Sum([]byte(fortune)))
			if err != nil {
				f_api_rf()
				http.Error(w, "JSON encoding is really difficult, I'm sorry I failed you", http.StatusInternalServerError)
				logrequest(r, "Failed to JSON encode fortune %s: %v", fid, err)
				return
			}
		}
		s_api_rf()
	})
	s_api_rfdb, f_api_rfdb := fs.Register("GET", "/api/v0/fortune/:db")
	router.GET("/api/v0/fortune/:db", func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		db, ok := fdb.DBs[ps.ByName("db")]
		if !ok {
			http.NotFound(w, r)
			f_api_rfdb()
			return
		}
		fortune, err := db.Random()
		if err != nil {
			http.Error(
				w,
				"Bad stuff happened, no soup for you",
				http.StatusInternalServerError)
			logrequest(r, "Failed to fetch fortune for %s: %v", ps.ByName("db"), err)
			f_api_rfdb()
			return
		}
		if err = NewV0(fortune).Emit(w); err != nil {
			http.Error(w, "Making JSON is hard", http.StatusInternalServerError)
			logrequest(r, "Failed to emit json: %v", err)
			f_api_rfdb()
			return
		}
		s_api_rfdb()
	})
	s_api_perm, f_api_perm := fs.Register("GET", "/api/v0/permalink/:id")
	router.GET("/api/v0/permalink/:id", func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		fid := ps.ByName("id")
		fortune, err := fdb.GetByPermalink(fid)
		if err != nil {
			http.Error(w, "Failed to fetch your fortune", http.StatusInternalServerError)
			logrequest(r, "Failed to look up fortune %s: %v", fid, err)
			f_api_perm()
			return
		}
		if err := NewV0(fortune).Emit(w); err != nil {
			logrequest(r, "Failed to emit fortune: %v", err)
			http.Error(w, "Failed to make your cookie", http.StatusInternalServerError)
			f_api_perm()
			return
		}
		s_api_perm()
	})
	router.GET("/static/:fn", func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		fn := ps.ByName("fn")
		if strings.HasSuffix(fn, ".css") || strings.HasSuffix(fn, ".html") || strings.HasSuffix(fn, ".js") {
			http.ServeFile(w, r, fmt.Sprintf("%s/%s", *static, fn))
		} else {
			http.NotFound(w, r)
		}
	})
	s_get_root, f_get_root := fs.Register("GET", "/")
	router.GET("/", func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		start := time.Now()
		fortune, err := fdb.Random()
		html := false
		if err != nil {
			http.Error(w, "Bad stuff happened", http.StatusInternalServerError)
			f_get_root()
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
		if err != nil {
			f_get_root()
		} else {
			s_get_root()
		}
		logrequest(r, "served random with err=%v html=%v in %v", err, html, time.Now().Sub(start))
	})
	s_get_db, f_get_db := fs.Register("GET", "/db/:db")
	router.GET("/db/:db", func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		html := false
		db, ok := fdb.DBs[ps.ByName("db")]
		if !ok {
			http.NotFound(w, r)
			f_get_db()
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
		if err == nil {
			s_get_db()
		} else {
			f_get_db()
		}
		logrequest(r, "served random for %s err=%v", ps.ByName("db"), err)
	})
	s_get_dbs, _ := fs.Register("GET", "/db")
	router.GET("/db", func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		for k := range fdb.DBs {
			w.Write([]byte(k))
			w.Write([]byte("\n"))
		}
		s_get_dbs()
	})
	s_get_permalink, f_get_permalink := fs.Register("GET", "/permalink/:id")
	router.GET("/permalink/:id", func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		start := time.Now()
		fortune, err := fdb.GetByPermalink(ps.ByName("id"))
		if err != nil {
			logrequest(r, "Failed to get by permalink %s: %v", ps.ByName("id"), err)
			http.Error(w, "Bad stuff happened", http.StatusInternalServerError)
			f_get_permalink()
		} else {
			io.WriteString(w, fortune)
			s_get_permalink()
		}
		logrequest(r, "served with err=%v in %v", err, time.Now().Sub(start))
	})
	srv := &http.Server{Addr: *listen, Handler: router}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	if os.Geteuid() == 0 || os.Getuid() == 0 {
		dropprivs()
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
