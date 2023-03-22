package main

import (
	"crypto/sha1"
	"flag"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/xtaci/kcp-go/v5"
	"golang.org/x/crypto/pbkdf2"
)

var (
	sport string
	saddr string
	iscry int
)

func init() {
	flag.IntVar(&iscry, "c", 0, "Encryption Need 1:en 0:non")
	flag.StringVar(&sport, "p", "60522", "server port nocrypt")
	flag.StringVar(&saddr, "s", "149.248.0.225", "server address US")
	flag.Parse()
}

func main() {

	key := pbkdf2.Key([]byte("demo pass"), []byte("demo salt"), 1024, 32, sha1.New)
	var block kcp.BlockCrypt

	if iscry == 1 {
		block, _ = kcp.NewAESBlockCrypt(key) //60422
		sport = "60422"
	} else {
		block, _ = kcp.NewNoneBlockCrypt(key) //60522
		sport = "60522"
	}

	fmt.Printf("ip:%v port:%v encryption:%v\n", saddr, sport, iscry)

	// dial to the echo server
	if sess, err := kcp.DialWithOptions(saddr+":"+sport, block, 10, 3); err == nil {
		for {
			data := time.Now().Local().String() + "<==>" + sess.RemoteAddr().String()
			buf := make([]byte, len(data))
			log.Println("sent:", data)
			if _, err := sess.Write([]byte(data)); err == nil {
				// read back the data
				if _, err := io.ReadFull(sess, buf); err == nil {
					log.Println("recv:", string(buf))
				} else {
					log.Fatal(err)
				}
			} else {
				log.Fatal(err)
			}
			time.Sleep(time.Millisecond * 12)
		}
	} else {
		log.Fatal(err)
	}
}
