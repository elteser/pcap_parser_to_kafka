package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"
)

func main() {
	// _globalHeaderSent := false

	fmt.Printf("Starting...\n")

	file, err := os.Open("test.pcap")
	defer file.Close()
	if err != nil {
		log.Fatal(err)
	}

	src := readNextBytes(file, 24)
	globalHeader := fmt.Sprintf("%x", src)

	if strings.HasPrefix(globalHeader, "d4c3b2a1") {
		fmt.Printf("%s", hex.Dump(src))

		pcapHeader := readNextBytes(file, 16)
		fmt.Printf("%s", hex.Dump(pcapHeader))

		ts := pcapHeader[0:8]
		fmt.Printf("%s", hex.Dump(ts))

		inclLenght := pcapHeader[8:12]
		fmt.Printf("%s", hex.Dump(inclLenght))
		a := binary.LittleEndian.Uint32(inclLenght)
		i := int(a)
		fmt.Println("This is: ", a)

		pcapData := readNextBytes(file, i)
		fmt.Printf("%s", hex.Dump(pcapData))

		f, err := os.OpenFile("out.pcap", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()

		var buf bytes.Buffer
		binary.Write(&buf, binary.BigEndian, pcapHeader)
		_, err = f.Write(buf.Bytes())

		if err != nil {
			log.Fatal(err)
		}

	} else {
		fmt.Println("Mismatch magic number")
	}

}

func readNextBytes(file *os.File, number int) []byte {
	bytes := make([]byte, number)

	_, err := file.Read(bytes)
	if err != nil {
		log.Fatal(err)
	}

	return bytes
}

// func writeFile() {
// 	file, err := os.Create("out.pcap")
// 	defer file.Close()
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	var bin_buf bytes.Buffer
// 	binary.Write(&bin_buf, binary.BigEndian, bytes []byte)
// }

// func writeNextBytes(file *os.File, bytes []byte) {

// 	_, err := file.Write(bytes)
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// }
