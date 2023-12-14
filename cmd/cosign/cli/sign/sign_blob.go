//
// Copyright 2021 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sign

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
	"os"
	"path/filepath"

	"github.com/ryboe/q"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/rekor"
	internal "github.com/sigstore/cosign/v2/internal/pkg/cosign"
	"github.com/sigstore/cosign/v2/internal/pkg/cosign/tsa"
	"github.com/sigstore/cosign/v2/internal/pkg/cosign/tsa/client"
	"github.com/sigstore/cosign/v2/internal/ui"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	cbundle "github.com/sigstore/cosign/v2/pkg/cosign/bundle"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	signatureoptions "github.com/sigstore/sigstore/pkg/signature/options"
)

// nolint
func SignBlobCmd(ro *options.RootOptions, ko options.KeyOpts, payloadPath string, b64 bool, outputSignature string, outputCertificate string, tlogUpload bool) ([]byte, error) {
	var payload internal.HashReader
	var err error

	ctx, cancel := context.WithTimeout(context.Background(), ro.Timeout)
	defer cancel()

	var msg []byte

	if payloadPath == "-" {
		// TODO: payload to sign is actually the Wasm hashes, which also uses SHA256, which
		// is great. But they shouldn't be read, and then hashed again, though? Or can we
		// make it work like that too? E.g. sort of double hashing that way. The thing is we
		// want to use the public key in the cert (which can be Ed25519) to verify the signature
		// over the Wasm module. So we need to sign those hashes, record the output, put that in
		// the Wasm (or detached), then upload the signature. I think a new command _may_ make
		// sense for this, so that we can read the Wasm immediately, then sign it, and record
		// the hash.
		payload = internal.NewHashReader(os.Stdin, sha256.New())
	} else {
		ui.Infof(ctx, "Using payload from: %s", payloadPath)
		f, err := os.Open(filepath.Clean(payloadPath))
		if err != nil {
			return nil, err
		}
		payload = internal.NewHashReader(f, sha256.New())
		msg, _ = os.ReadFile(f.Name())
	}
	if err != nil {
		return nil, err
	}

	hf := func() hash.Hash {
		fmt.Println("returning custom hash")
		return &customHash{state: []byte{}}
	}
	crypto.RegisterHash(crypto.Hash(1), hf)

	wasmMsg, err := base64.StdEncoding.DecodeString("d2FzbXNpZwEBAePYQL+P/sl8K6Cvs9tnJrKcijdPTphkb3PbXTUdTg9v")
	if err != nil {
		return nil, err
	}

	wasmDigest := sha512.Sum512(wasmMsg)

	payload = internal.NewHashReader(bytes.NewReader(wasmDigest[:]), crypto.Hash(1).New()) // fake hash; just return the bytes (I hope)

	q.Q(payload)

	sv, err := SignerFromKeyOpts(ctx, "", "", ko)
	if err != nil {
		return nil, err
	}
	defer sv.Close()

	sig, err := sv.SignMessage(&payload, signatureoptions.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("signing blob: %w", err)
	}

	q.Q(sig)

	signedPayload := cosign.LocalSignedPayload{}

	var rfc3161Timestamp *cbundle.RFC3161Timestamp
	if ko.TSAServerURL != "" {
		if ko.RFC3161TimestampPath == "" {
			return nil, fmt.Errorf("timestamp output path must be set")
		}
		var respBytes []byte
		var err error
		if ko.TSAClientCACert == "" && ko.TSAClientCert == "" { // no mTLS params or custom CA
			respBytes, err = tsa.GetTimestampedSignature(sig, client.NewTSAClient(ko.TSAServerURL))
			if err != nil {
				return nil, err
			}
		} else {
			respBytes, err = tsa.GetTimestampedSignature(sig, client.NewTSAClientMTLS(ko.TSAServerURL,
				ko.TSAClientCACert,
				ko.TSAClientCert,
				ko.TSAClientKey,
				ko.TSAServerName,
			))
			if err != nil {
				return nil, err
			}
		}

		rfc3161Timestamp = cbundle.TimestampToRFC3161Timestamp(respBytes)
		// TODO: Consider uploading RFC3161 TS to Rekor

		if rfc3161Timestamp == nil {
			return nil, fmt.Errorf("rfc3161 timestamp is nil")
		}
		ts, err := json.Marshal(rfc3161Timestamp)
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(ko.RFC3161TimestampPath, ts, 0600); err != nil {
			return nil, fmt.Errorf("create RFC3161 timestamp file: %w", err)
		}
		ui.Infof(ctx, "RFC3161 timestamp written to file %s\n", ko.RFC3161TimestampPath)
	}
	shouldUpload, err := ShouldUploadToTlog(ctx, ko, nil, tlogUpload)
	if err != nil {
		return nil, fmt.Errorf("upload to tlog: %w", err)
	}
	if shouldUpload {
		rekorBytes, err := sv.Bytes(ctx)
		if err != nil {
			return nil, err
		}
		rekorClient, err := rekor.NewClient(ko.RekorURL)
		if err != nil {
			return nil, err
		}

		// if sig == nil {
		// 	return nil, nil, types.ValidationError(errors.New("missing signature"))
		// }
		// // Hashed rekord type only works for x509 signature types
		// sigObj, err := x509.NewSignature(bytes.NewReader(sig.Content))
		// if err != nil {
		// 	return nil, nil, types.ValidationError(err)
		// }

		// key := sig.PublicKey
		// if key == nil {
		// 	return nil, nil, types.ValidationError(errors.New("missing public key"))
		// }
		// keyObj, err := x509.NewPublicKey(bytes.NewReader(key.Content))
		// if err != nil {
		// 	return nil, nil, types.ValidationError(err)
		// }

		// verifier, err := sigsig.LoadVerifier(p, crypto.SHA256)
		// if err != nil {
		// 	return err
		// }

		// decoded, err := io.ReadAll(&payload)
		// if err != nil {
		// 	return nil, fmt.Errorf("failed reading payload: %w", err)
		// }

		q.Q(msg)

		err = sv.VerifySignature(bytes.NewReader(sig), bytes.NewBuffer(wasmDigest[:]))
		if err != nil {
			return nil, fmt.Errorf("failed verifying payload: %w", err)
		}

		entry, err := cosign.TLogUpload(ctx, rekorClient, sig, &payload, rekorBytes)
		if err != nil {
			return nil, err
		}
		ui.Infof(ctx, "tlog entry created with index: %d", *entry.LogIndex)
		signedPayload.Bundle = cbundle.EntryToBundle(entry)
	}

	// if bundle is specified, just do that and ignore the rest
	if ko.BundlePath != "" {
		signedPayload.Base64Signature = base64.StdEncoding.EncodeToString(sig)

		certBytes, err := extractCertificate(ctx, sv)
		if err != nil {
			return nil, err
		}
		signedPayload.Cert = base64.StdEncoding.EncodeToString(certBytes)

		contents, err := json.Marshal(signedPayload)
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(ko.BundlePath, contents, 0600); err != nil {
			return nil, fmt.Errorf("create bundle file: %w", err)
		}
		ui.Infof(ctx, "Wrote bundle to file %s", ko.BundlePath)
	}

	if outputSignature != "" {
		var bts = sig
		if b64 {
			bts = []byte(base64.StdEncoding.EncodeToString(sig))
		}
		if err := os.WriteFile(outputSignature, bts, 0600); err != nil {
			return nil, fmt.Errorf("create signature file: %w", err)
		}
		ui.Infof(ctx, "Wrote signature to file %s", outputSignature)
	} else {
		if b64 {
			sig = []byte(base64.StdEncoding.EncodeToString(sig))
			fmt.Println(string(sig))
		} else if _, err := os.Stdout.Write(sig); err != nil {
			// No newline if using the raw signature
			return nil, err
		}
	}

	if outputCertificate != "" {
		certBytes, err := extractCertificate(ctx, sv)
		if err != nil {
			return nil, err
		}
		if certBytes != nil {
			bts := certBytes
			if b64 {
				bts = []byte(base64.StdEncoding.EncodeToString(certBytes))
			}
			if err := os.WriteFile(outputCertificate, bts, 0600); err != nil {
				return nil, fmt.Errorf("create certificate file: %w", err)
			}
			ui.Infof(ctx, "Wrote certificate to file %s", outputCertificate)
		}
	}

	return sig, nil
}

// Extract an encoded certificate from the SignerVerifier. Returns (nil, nil) if verifier is not a certificate.
func extractCertificate(ctx context.Context, sv *SignerVerifier) ([]byte, error) {
	signer, err := sv.Bytes(ctx)
	if err != nil {
		return nil, fmt.Errorf("error getting signer: %w", err)
	}
	cert, err := cryptoutils.UnmarshalCertificatesFromPEM(signer)
	// signer is a certificate
	if err == nil && len(cert) == 1 {
		return signer, nil
	}
	return nil, nil
}

type customHash struct {
	state []byte
}

func (h *customHash) BlockSize() int {
	return 64
}

func (h *customHash) Size() int {
	return 64
}

func (h *customHash) Reset() {
	h.state = []byte{}
}

func (h *customHash) Sum(b []byte) []byte {
	return h.state
}

func (h *customHash) Write(b []byte) (int, error) {
	fmt.Println("writing", len(b))
	h.state = b
	return len(b), nil
}

var _ hash.Hash = (*customHash)(nil)
