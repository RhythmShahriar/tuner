// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: AGPL-3.0-only

package report

import (
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

// MaxLogoSize is the largest brand logo the HTML report embeds.
const MaxLogoSize = 512 << 10

// LogoDataURI reads a brand logo and returns it as a data: URI for the
// HTML report: a PNG or JPEG as it is, an SVG rebuilt from an allow-list
// of shapes and attributes. Anything else, a file over MaxLogoSize or an
// SVG with scripts, links or styles is an error, so a logo can't run
// code or load anything when a client opens the report.
func LogoDataURI(path string) (string, error) {
	f, err := os.Open(path) //nolint:gosec // the user names their own logo
	if err != nil {
		return "", fmt.Errorf("brand logo: %w", err)
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, MaxLogoSize+1))
	if err != nil {
		return "", fmt.Errorf("brand logo: %w", err)
	}
	if len(data) > MaxLogoSize {
		return "", fmt.Errorf("brand logo %s is over %d KB; use a smaller file", SafeText(path), MaxLogoSize>>10)
	}
	var mime string
	switch {
	case bytes.HasPrefix(data, []byte("\x89PNG\r\n\x1a\n")):
		mime = "image/png"
	case bytes.HasPrefix(data, []byte("\xff\xd8\xff")):
		mime = "image/jpeg"
	default:
		clean, err := sanitizeSVG(data)
		if err != nil {
			return "", fmt.Errorf("brand logo %s: %w", SafeText(path), err)
		}
		mime, data = "image/svg+xml", clean
	}
	return "data:" + mime + ";base64," + base64.StdEncoding.EncodeToString(data), nil
}

// svgNS is the namespace a logo's root element must declare.
const svgNS = "http://www.w3.org/2000/svg"

// svgElements are the SVG elements a logo may use: shapes, text, groups
// and gradients. Scripts, foreignObject, use, image, a, style and
// animation are left out because each can run code or fetch a URL.
var svgElements = map[string]bool{
	"svg": true, "g": true, "path": true, "rect": true, "circle": true, "ellipse": true,
	"line": true, "polyline": true, "polygon": true, "text": true, "tspan": true,
	"defs": true, "linearGradient": true, "radialGradient": true, "stop": true,
	"clipPath": true, "mask": true, "title": true, "desc": true,
}

// svgAttrs are the attributes a logo may use. Event handlers, href,
// style and anything namespaced are left out.
var svgAttrs = map[string]bool{
	"id": true, "class": true, "viewBox": true, "width": true, "height": true, "version": true,
	"preserveAspectRatio": true, "x": true, "y": true, "x1": true, "y1": true, "x2": true, "y2": true,
	"cx": true, "cy": true, "r": true, "rx": true, "ry": true, "fx": true, "fy": true, "d": true, "points": true,
	"transform": true, "fill": true, "fill-opacity": true, "fill-rule": true, "stroke": true,
	"stroke-width": true, "stroke-linecap": true, "stroke-linejoin": true, "stroke-miterlimit": true,
	"stroke-dasharray": true, "stroke-dashoffset": true, "stroke-opacity": true, "opacity": true,
	"offset": true, "stop-color": true, "stop-opacity": true, "gradientUnits": true, "gradientTransform": true,
	"spreadMethod": true, "clip-path": true, "clip-rule": true, "clipPathUnits": true, "mask": true,
	"maskUnits": true, "font-family": true, "font-size": true, "font-weight": true, "font-style": true,
	"text-anchor": true, "dominant-baseline": true, "letter-spacing": true, "dx": true, "dy": true,
}

// sanitizeSVG parses an SVG and writes it again from what it parsed,
// keeping only allowed elements and attributes. What the browser gets is
// exactly what was checked, so parser differences can't smuggle markup
// past the check. Comments are dropped; a DOCTYPE (which can define
// entities), a processing instruction or a disallowed element or
// attribute is an error.
func sanitizeSVG(data []byte) ([]byte, error) {
	d := xml.NewDecoder(bytes.NewReader(data))
	d.Strict = true
	var (
		out   bytes.Buffer
		depth int
		root  bool
	)
	for {
		tok, err := d.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, errors.New("want a PNG, JPEG or SVG file")
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if t.Name.Space != "" && t.Name.Space != svgNS {
				return nil, fmt.Errorf("<%s> from another namespace is not allowed in an SVG logo", SafeText(t.Name.Local))
			}
			if !svgElements[t.Name.Local] {
				return nil, fmt.Errorf("<%s> is not allowed in an SVG logo", SafeText(t.Name.Local))
			}
			if depth == 0 {
				if root || t.Name.Local != "svg" {
					return nil, errors.New("want a PNG, JPEG or SVG file")
				}
				root = true
			}
			depth++
			out.WriteString("<" + t.Name.Local)
			if depth == 1 {
				out.WriteString(` xmlns="` + svgNS + `"`)
			}
			for _, a := range t.Attr {
				if a.Name.Space == "xmlns" || (a.Name.Space == "" && a.Name.Local == "xmlns") {
					continue // the root gets the SVG namespace; nothing else is kept
				}
				if a.Name.Space != "" || !svgAttrs[a.Name.Local] {
					return nil, fmt.Errorf("attribute %q is not allowed in an SVG logo", SafeText(a.Name.Local))
				}
				if !safeValue(a.Value) {
					return nil, fmt.Errorf("attribute %q points outside the logo", SafeText(a.Name.Local))
				}
				out.WriteString(" " + a.Name.Local + `="`)
				_ = xml.EscapeText(&out, []byte(a.Value))
				out.WriteString(`"`)
			}
			out.WriteString(">")
		case xml.EndElement:
			depth--
			out.WriteString("</" + t.Name.Local + ">")
		case xml.CharData:
			if depth > 0 {
				_ = xml.EscapeText(&out, t)
			}
		case xml.ProcInst:
			if t.Target != "xml" {
				return nil, errors.New("processing instructions are not allowed in an SVG logo")
			}
		case xml.Directive:
			return nil, errors.New("a DOCTYPE is not allowed in an SVG logo")
		case xml.Comment: // dropped
		}
	}
	if !root {
		return nil, errors.New("want a PNG, JPEG or SVG file")
	}
	return out.Bytes(), nil
}

// svgFuncs are the functions an attribute value may call besides
// url(#id): transforms and colors, with plain numbers for arguments.
var svgFuncs = map[string]bool{
	"matrix": true, "translate": true, "scale": true, "rotate": true, "skewx": true, "skewy": true,
	"rgb": true, "rgba": true, "hsl": true, "hsla": true,
}

var (
	// svgLocalURL is url(#id), the only url() a logo may hold.
	svgLocalURL = regexp.MustCompile(`^url\(\s*(?:#[\w.:-]+|"#[\w.:-]+"|'#[\w.:-]+')\s*\)`)
	// svgCall is an allowed function with numeric arguments.
	svgCall = regexp.MustCompile(`^([a-z]+)\(\s*[-+0-9.,e%\s]*\)`)
)

// safeValue reports whether an attribute value can't reach outside the
// logo. A backslash is refused outright because CSS escapes like
// "u\rl(" would read as url( to the browser but not to a substring
// check. Every "(" must open url(#id) or an allowed function of numbers.
func safeValue(v string) bool {
	if strings.Contains(v, "\\") {
		return false
	}
	v = strings.ToLower(v)
	for {
		i := strings.IndexByte(v, '(')
		if i < 0 {
			return true
		}
		start := i
		for start > 0 && v[start-1] >= 'a' && v[start-1] <= 'z' {
			start--
		}
		rest := v[start:]
		if m := svgLocalURL.FindString(rest); m != "" {
			v = rest[len(m):]
			continue
		}
		m := svgCall.FindStringSubmatch(rest)
		if m == nil || !svgFuncs[m[1]] {
			return false
		}
		v = rest[len(m[0]):]
	}
}
