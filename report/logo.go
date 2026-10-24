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
				if v := strings.ToLower(a.Value); strings.Contains(v, "url(") && !localRefs(v) {
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

// localRefs reports whether every url(...) in v points inside the
// document, like fill="url(#grad)".
func localRefs(v string) bool {
	for {
		i := strings.Index(v, "url(")
		if i < 0 {
			return true
		}
		v = strings.TrimLeft(v[i+4:], ` "'`)
		if !strings.HasPrefix(v, "#") {
			return false
		}
	}
}
