package api

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"html/template"
	"image"
	"image/color"
	"image/png"
	"math"
	"math/rand/v2"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/image/draw"
	"golang.org/x/image/font"
	"golang.org/x/image/font/gofont/gobold"
	"golang.org/x/image/font/opentype"
	"golang.org/x/image/math/f64"
	"golang.org/x/image/math/fixed"
)

const (
	loginTextImageWidth  = 240
	loginTextImageHeight = 72
)

var loginCaptchaTypeface = sync.OnceValues(func() (*opentype.Font, error) {
	return opentype.Parse(gobold.TTF)
})

func makeLoginCaptchaImage(code string) (template.URL, error) {
	const allowed = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+-−=? "
	runes := []rune(code)
	if len(runes) == 0 || len(runes) > 12 {
		return "", fmt.Errorf("captcha text length is invalid")
	}
	for _, char := range runes {
		if !strings.ContainsRune(allowed, char) {
			return "", fmt.Errorf("captcha contains an unsupported character")
		}
	}

	size := 31.0
	if len(runes) > 7 {
		size = 24
	}
	face, err := newLoginCaptchaFace(size)
	if err != nil {
		return "", err
	}
	defer face.Close()

	canvas := image.NewRGBA(image.Rect(0, 0, loginTextImageWidth, loginTextImageHeight))
	draw.Draw(canvas, canvas.Bounds(), image.NewUniform(color.RGBA{232, 238, 245, 255}), image.Point{}, draw.Src)
	inks := []color.RGBA{{23, 79, 112, 255}, {138, 61, 93, 255}, {54, 92, 59, 255}, {117, 77, 32, 255}, {67, 56, 202, 255}}
	noise := []color.RGBA{{177, 195, 212, 255}, {199, 174, 197, 255}, {173, 191, 181, 255}, {207, 189, 174, 255}, {184, 181, 219, 255}}
	drawCaptchaNoise(canvas, noise, 13, 30)

	slot := float64(loginTextImageWidth-24) / float64(len(runes))
	arithmetic := strings.ContainsRune(code, '=')
	for index, char := range runes {
		if char == ' ' {
			continue
		}
		x := 12 + slot*(float64(index)+0.5)
		y, angle := float64(loginTextImageHeight)/2, 0.0
		// Aligned digits and operators keep the arithmetic readable at native size.
		if !arithmetic {
			y += float64(rand.IntN(9) - 4)
			angle = float64(rand.IntN(31)-15) * math.Pi / 180
		}
		drawCaptchaGlyph(canvas, face, string(char), x, y, angle, inks[rand.IntN(len(inks))])
	}
	return encodeCaptchaPNG(canvas)
}

func makeLoginTraceCaptchaImage(points []loginCaptchaPoint) (template.URL, error) {
	face, err := newLoginCaptchaFace(21)
	if err != nil {
		return "", err
	}
	defer face.Close()

	canvas := image.NewRGBA(image.Rect(0, 0, loginTraceImageWidth, loginTraceImageHeight))
	draw.Draw(canvas, canvas.Bounds(), image.NewUniform(color.RGBA{25, 33, 57, 255}), image.Point{}, draw.Src)
	noise := []color.RGBA{{42, 75, 104, 255}, {59, 54, 106, 255}, {83, 48, 80, 255}, {79, 68, 56, 255}, {38, 76, 72, 255}}
	drawCaptchaNoise(canvas, noise, 17, 46)
	palettes := []struct{ fill, ring color.RGBA }{
		{color.RGBA{15, 118, 110, 255}, color.RGBA{94, 234, 212, 255}},
		{color.RGBA{29, 78, 216, 255}, color.RGBA{96, 165, 250, 255}},
		{color.RGBA{157, 23, 77, 255}, color.RGBA{244, 114, 182, 255}},
		{color.RGBA{143, 90, 15, 255}, color.RGBA{250, 204, 21, 255}},
		{color.RGBA{109, 40, 217, 255}, color.RGBA{196, 181, 253, 255}},
	}
	for _, point := range points {
		center := image.Pt(point.X*loginTraceImageWidth/100, point.Y*loginTraceImageHeight/100)
		if point.Decoy {
			fillCaptchaDisc(canvas, center, 15, color.RGBA{105, 124, 149, 255})
			fillCaptchaDisc(canvas, center, 13, color.RGBA{55, 65, 85, 255})
			fillCaptchaDisc(canvas, center, 3, color.RGBA{162, 176, 195, 255})
			continue
		}
		palette := palettes[rand.IntN(len(palettes))]
		fillCaptchaDisc(canvas, center, 17, palette.ring)
		fillCaptchaDisc(canvas, center, 15, palette.fill)
		angle := float64(rand.IntN(29)-14) * math.Pi / 180
		drawCaptchaGlyph(canvas, face, strconv.Itoa(point.Label), float64(center.X), float64(center.Y), angle, color.RGBA{248, 250, 252, 255})
	}
	return encodeCaptchaPNG(canvas)
}

func newLoginCaptchaFace(size float64) (font.Face, error) {
	typeface, err := loginCaptchaTypeface()
	if err != nil {
		return nil, err
	}
	return opentype.NewFace(typeface, &opentype.FaceOptions{Size: size, DPI: 72, Hinting: font.HintingNone})
}

func drawCaptchaGlyph(canvas *image.RGBA, face font.Face, text string, x, y, angle float64, ink color.RGBA) {
	bounds, _ := font.BoundString(face, text)
	left, top := bounds.Min.X.Floor(), bounds.Min.Y.Floor()
	width, height := bounds.Max.X.Ceil()-left, bounds.Max.Y.Ceil()-top
	if width <= 0 || height <= 0 {
		return
	}
	glyph := image.NewRGBA(image.Rect(0, 0, width, height))
	drawer := font.Drawer{Dst: glyph, Src: image.NewUniform(ink), Face: face, Dot: fixed.P(-left, -top)}
	drawer.DrawString(text)

	// Rotate about the glyph center so its position still matches the target.
	sin, cos := math.Sincos(angle)
	halfWidth, halfHeight := float64(width)/2, float64(height)/2
	transform := f64.Aff3{
		cos, -sin, x - cos*halfWidth + sin*halfHeight,
		sin, cos, y - sin*halfWidth - cos*halfHeight,
	}
	draw.BiLinear.Transform(canvas, transform, glyph, glyph.Bounds(), draw.Over, nil)
}

func drawCaptchaNoise(canvas *image.RGBA, palette []color.RGBA, strokes, dots int) {
	width, height := canvas.Bounds().Dx(), canvas.Bounds().Dy()
	for range strokes {
		start := image.Pt(rand.IntN(width), rand.IntN(height))
		end := image.Pt(rand.IntN(width), rand.IntN(height))
		dx, dy := float64(end.X-start.X), float64(end.Y-start.Y)
		steps := max(1, int(max(math.Abs(dx), math.Abs(dy))))
		ink := palette[rand.IntN(len(palette))]
		for step := 0; step <= steps; step++ {
			t := float64(step) / float64(steps)
			canvas.SetRGBA(start.X+int(math.Round(dx*t)), start.Y+int(math.Round(dy*t)), ink)
		}
	}
	for range dots {
		center := image.Pt(rand.IntN(width), rand.IntN(height))
		fillCaptchaDisc(canvas, center, 1+rand.IntN(2), palette[rand.IntN(len(palette))])
	}
}

func fillCaptchaDisc(canvas *image.RGBA, center image.Point, radius int, ink color.RGBA) {
	for y := -radius; y <= radius; y++ {
		for x := -radius; x <= radius; x++ {
			if x*x+y*y <= radius*radius {
				canvas.SetRGBA(center.X+x, center.Y+y, ink)
			}
		}
	}
}

func encodeCaptchaPNG(canvas image.Image) (template.URL, error) {
	// Send only pixels. A text-based image can expose characters and targets
	// even when the page never displays the expected answer as text.
	var encoded bytes.Buffer
	encoder := png.Encoder{CompressionLevel: png.BestSpeed}
	if err := encoder.Encode(&encoded, canvas); err != nil {
		return "", err
	}
	return template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(encoded.Bytes())), nil
}
