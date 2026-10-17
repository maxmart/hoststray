package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"image"
	"image/color"
	"image/png"
	"runtime"
)

// trayIcon returns the tray icon tinted green (proxy on) or gray (off), as
// PNG, or wrapped in an ICO container on Windows.
func trayIcon(proxyOn bool) []byte {
	raw, _ := base64.StdEncoding.DecodeString(baseIconPNG)
	src, err := png.Decode(bytes.NewReader(raw))
	if err != nil {
		return raw
	}
	b := src.Bounds()
	dst := image.NewNRGBA(b)
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			c := color.NRGBAModel.Convert(src.At(x, y)).(color.NRGBA)
			if c.A >= 10 {
				r, g, bl := float64(c.R), float64(c.G), float64(c.B)
				if proxyOn {
					c.R, c.G, c.B = uint8(r*0.3), uint8(min(255, g*0.5+128)), uint8(bl*0.3)
				} else {
					gray := uint8(0.299*r + 0.587*g + 0.114*bl)
					c.R, c.G, c.B = gray, gray, gray
				}
			}
			dst.Set(x, y, c)
		}
	}
	var out bytes.Buffer
	png.Encode(&out, dst)
	if runtime.GOOS == "windows" {
		return pngToICO(out.Bytes(), b.Dx(), b.Dy())
	}
	return out.Bytes()
}

// pngToICO wraps a PNG in a single-image ICO file (Vista+ reads PNG entries).
func pngToICO(p []byte, w, h int) []byte {
	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, []uint16{0, 1, 1}) // reserved, type=icon, count
	buf.Write([]byte{byte(w), byte(h), 0, 0})                  // width, height, colors, reserved
	binary.Write(&buf, binary.LittleEndian, []uint16{1, 32})   // planes, bits per pixel
	binary.Write(&buf, binary.LittleEndian, []uint32{uint32(len(p)), 22})
	buf.Write(p)
	return buf.Bytes()
}
