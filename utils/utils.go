package utils

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"google.golang.org/protobuf/proto"
)

func GetServerStoragePathByNames(packageNames ...string) string {
	if len(packageNames) == 0 {
		return ""
	}
	return filepath.Join(packageNames...)
}

func IsFileExist(path string) bool {
	_, err := os.Stat(path)
	return err == nil || os.IsExist(err)
}

func Md5(str string) string {
	h := md5.New()
	h.Write([]byte(str))
	return hex.EncodeToString(h.Sum(nil))
}

func DecodeYaml(yamlContent string, keyVal map[string]string) string {
	for key, val := range keyVal {
		placeholder := "{" + key + "}"
		yamlContent = strings.ReplaceAll(yamlContent, placeholder, val)
	}
	return yamlContent
}

func WriteFile(filePath, content string) error {
	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to open or create file: %w", err)
	}
	defer file.Close()
	if _, err := io.WriteString(file, content); err != nil {
		return fmt.Errorf("failed to write to file: %w", err)
	}
	return nil
}

// ReadLastNLines reads the last n lines from a file.
func ReadLastNLines(file *os.File, n int) (string, error) {
	if n <= 0 {
		return "", fmt.Errorf("invalid number of lines: %d", n)
	}

	stat, err := file.Stat()
	if err != nil {
		return "", err
	}

	fileSize := stat.Size()
	if fileSize == 0 {
		return "", nil
	}

	bufferSize := 1024
	buf := make([]byte, bufferSize)
	lines := make([]string, 0, n)
	offset := int64(0)
	lineCount := 0

	for offset < fileSize && lineCount < n {
		readSize := min(bufferSize, int(fileSize-offset))
		offset += int64(readSize)

		_, err := file.Seek(-offset, io.SeekEnd)
		if err != nil {
			return "", err
		}

		_, err = file.Read(buf[:readSize])
		if err != nil {
			return "", err
		}

		// Reverse the buffer to process lines from end to start
		for i := readSize - 1; i >= 0 && lineCount < n; i-- {
			if buf[i] == '\n' || i == 0 {
				start := i
				if buf[i] == '\n' {
					start++
				}
				line := string(buf[start:readSize])
				if line != "" || i == 0 {
					lines = append([]string{line}, lines...)
					lineCount++
					readSize = i
				}
			}
		}
	}
	return strings.Join(lines, "\n"), nil
}

func MergePath(paths ...string) string {
	pathArr := make([]string, 0)
	for _, path := range paths {
		pathArr = append(pathArr, strings.Split(path, "/")...)
	}
	return strings.Join(pathArr, "/")
}

func DownloadFile(rawURL string) (string, error) {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	path := parsedURL.Path
	fileName := filepath.Base(path)

	if fileName == "" {
		return "", fmt.Errorf("failed to get file name from URL")
	}

	if IsFileExist(fileName) {
		return fileName, nil
	}

	out, err := os.Create(fileName)
	if err != nil {
		return "", err
	}
	defer out.Close()

	resp, err := http.Get(rawURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return "", err
	}

	return fileName, nil
}

func SerializeToBase64(msg proto.Message) (string, error) {
	data, err := proto.Marshal(msg)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

func DeserializeFromBase64(data string, msg proto.Message) error {
	decoded, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return err
	}
	return proto.Unmarshal(decoded, msg)
}

// example: startIp 192.168.0.1 endIp 192.168.0.254, return 192.168.0.1 192.168.0.2 .... 192.168.0.254
func RangeIps(startIp, endIp string) []string {
	var result []string

	start := ip4ToUint32(startIp)
	end := ip4ToUint32(endIp)

	if start > end {
		return result
	}

	for i := start; i <= end; i++ {
		result = append(result, uint32ToIp4(i))
	}

	return result
}

func ip4ToUint32(ip string) uint32 {
	bits := strings.Split(ip, ".")
	if len(bits) != 4 {
		return 0
	}

	b0, _ := strconv.Atoi(bits[0])
	b1, _ := strconv.Atoi(bits[1])
	b2, _ := strconv.Atoi(bits[2])
	b3, _ := strconv.Atoi(bits[3])

	var sum uint32
	sum += uint32(b0) << 24
	sum += uint32(b1) << 16
	sum += uint32(b2) << 8
	sum += uint32(b3)

	return sum
}

func uint32ToIp4(ipInt uint32) string {
	b0 := ((ipInt >> 24) & 0xFF)
	b1 := ((ipInt >> 16) & 0xFF)
	b2 := ((ipInt >> 8) & 0xFF)
	b3 := (ipInt & 0xFF)

	return fmt.Sprintf("%d.%d.%d.%d", b0, b1, b2, b3)
}
