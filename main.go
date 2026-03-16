package main

import (
	"crypto/aes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

// ── EID functions — copied from beacon/eid.go (keep in sync) ─────────────────

func generateTemporaryKey(eidKey []byte, timeCounter uint32) ([16]byte, error) {
	block, err := aes.NewCipher(eidKey)
	if err != nil {
		return [16]byte{}, err
	}
	top16 := uint16(timeCounter >> 16)
	var pt [16]byte
	pt[11] = 0xFF
	binary.BigEndian.PutUint16(pt[14:], top16)
	var tmpKey [16]byte
	block.Encrypt(tmpKey[:], pt[:])
	return tmpKey, nil
}

func computeEID(eidKey []byte, timeCounter uint32, rotExp uint8) ([8]byte, error) {
	if len(eidKey) != 16 {
		return [8]byte{}, fmt.Errorf("eidKey must be 16 bytes")
	}
	if rotExp >= 16 {
		return [8]byte{}, fmt.Errorf("rotation exponent must be in [0,15]")
	}
	tmpKey, err := generateTemporaryKey(eidKey, timeCounter)
	if err != nil {
		return [8]byte{}, err
	}
	block, err := aes.NewCipher(tmpKey[:])
	if err != nil {
		return [8]byte{}, err
	}
	rounded := (timeCounter >> rotExp) << rotExp
	var pt [16]byte
	pt[11] = rotExp
	binary.BigEndian.PutUint32(pt[12:], rounded)
	var ct [16]byte
	block.Encrypt(ct[:], pt[:])
	var out [8]byte
	copy(out[:], ct[:8])
	return out, nil
}

func humanDuration(secs int64) string {
	if secs < 60 {
		return fmt.Sprintf("%ds", secs)
	} else if secs < 3600 {
		return fmt.Sprintf("%dm %ds", secs/60, secs%60)
	}
	h := secs / 3600
	m := (secs % 3600) / 60
	s := secs % 60
	return fmt.Sprintf("%dh %dm %ds", h, m, s)
}

// ── Profiles ─────────────────────────────────────────────────────────────────

type Profile struct {
	Name         string `json:"name"`
	Key          string `json:"key"`
	BaseTimeUnix int64  `json:"base_time_unix"`
	RotationExp  int    `json:"rotation_exp"`
}

const profilesFile = "profiles.json"

func loadProfiles() ([]Profile, error) {
	data, err := os.ReadFile(profilesFile)
	if os.IsNotExist(err) {
		return []Profile{}, nil
	}
	if err != nil {
		return nil, err
	}
	var profiles []Profile
	return profiles, json.Unmarshal(data, &profiles)
}

func saveProfiles(profiles []Profile) error {
	data, err := json.MarshalIndent(profiles, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(profilesFile, data, 0644)
}

// ── Handlers ──────────────────────────────────────────────────────────────────

func withCORS(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		h(w, r)
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func handleProfiles(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		profiles, err := loadProfiles()
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, profiles)

	case http.MethodPost:
		var p Profile
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil || p.Name == "" {
			writeJSON(w, 400, map[string]string{"error": "invalid body"})
			return
		}
		profiles, _ := loadProfiles()
		filtered := profiles[:0]
		for _, x := range profiles {
			if x.Name != p.Name {
				filtered = append(filtered, x)
			}
		}
		filtered = append(filtered, p)
		saveProfiles(filtered)
		writeJSON(w, 200, map[string]bool{"ok": true})

	case http.MethodDelete:
		name := strings.TrimPrefix(r.URL.Path, "/api/profiles/")
		profiles, _ := loadProfiles()
		filtered := profiles[:0]
		for _, x := range profiles {
			if x.Name != name {
				filtered = append(filtered, x)
			}
		}
		saveProfiles(filtered)
		writeJSON(w, 200, map[string]bool{"ok": true})
	}
}

func handleValidate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Key          string `json:"key"`
		BaseTimeUnix int64  `json:"base_time_unix"`
		EID          string `json:"eid"`
		Timestamp    string `json:"timestamp"`
		RotationExp  int    `json:"rotation_exp"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid body"})
		return
	}

	keyBytes, err := hex.DecodeString(req.Key)
	if err != nil || len(keyBytes) != 16 {
		writeJSON(w, 400, map[string]string{"error": "key must be 32 hex characters"})
		return
	}

	targetEID, err := hex.DecodeString(req.EID)
	if err != nil || len(targetEID) != 8 {
		writeJSON(w, 400, map[string]string{"error": "eid must be 16 hex characters"})
		return
	}

	ts, err := time.Parse(time.RFC3339, req.Timestamp)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid timestamp, use RFC3339 e.g. 2026-03-16T18:39:30+05:30"})
		return
	}

	timeUnix := ts.Unix()
	baseCounter := timeUnix - req.BaseTimeUnix

	// try specified rotExp; if -1 try all 0-15
	rotExps := []int{req.RotationExp}
	if req.RotationExp < 0 {
		for i := 0; i <= 15; i++ {
			rotExps = append(rotExps, i)
		}
	}

	const tolerance = 10
	for _, rot := range rotExps {
		for d := -tolerance; d <= tolerance; d++ {
			counter := uint32(baseCounter + int64(d))
			eid, err := computeEID(keyBytes, counter, uint8(rot))
			if err != nil {
				continue
			}
			if strings.ToUpper(hex.EncodeToString(eid[:])) == strings.ToUpper(req.EID) {
				computed, _ := computeEID(keyBytes, uint32(baseCounter), uint8(req.RotationExp))
				writeJSON(w, 200, map[string]any{
					"valid":           true,
					"rotation_exp":    rot,
					"counter":         counter,
					"counter_human":   humanDuration(time.Now().Unix() - req.BaseTimeUnix),
					"rotation_window": humanDuration(int64(1) << rot),
					"offset_s":        d,
					"computed":        strings.ToUpper(hex.EncodeToString(computed[:])),
				})
				return
			}
		}
	}

	computed, _ := computeEID(keyBytes, uint32(baseCounter), uint8(req.RotationExp))
	writeJSON(w, 200, map[string]any{
		"valid":           false,
		"counter":         baseCounter,
		"counter_human":   humanDuration(time.Now().Unix() - req.BaseTimeUnix),
		"rotation_window": humanDuration(int64(1) << req.RotationExp),
		"computed":        strings.ToUpper(hex.EncodeToString(computed[:])),
	})
}


func main() {
	mux := http.NewServeMux()

	// static
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "index.html")
	})
	mux.HandleFunc("/provision", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "provision/index.html")
	})
	mux.HandleFunc("/validate", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "validate/index.html")
	})
	mux.HandleFunc("/read-eid", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "read-eid/index.html")
	})

	// api
	mux.HandleFunc("/api/profiles", withCORS(handleProfiles))
	mux.HandleFunc("/api/profiles/", withCORS(handleProfiles))
	mux.HandleFunc("/api/validate", withCORS(handleValidate))

log.Println("Beacon EID Validator  → http://localhost:8765")
	log.Println("Beacon Provisioner    → http://localhost:8765/provision")
	log.Fatal(http.ListenAndServe(":8765", mux))
}
