package chisel

import (
	"context"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/klauspost/compress/zstd"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/digest"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/mapfs"
)

func Test_chiselAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name string
		// testFiles contains path in testdata and path in OS
		// e.g. tar.list => var/lib/dpkg/info/tar.list
		testFiles map[string]string
		want      *analyzer.AnalysisResult
		wantErr   bool
	}{
		{
			name:      "libc6",
			testFiles: map[string]string{"./testdata/libc6.manifest.wall": "var/lib/chisel/manifest.wall"},
			want: &analyzer.AnalysisResult{
				OS: types.OS{Family: types.Ubuntu},
				PackageInfos: []types.PackageInfo{
					{
						FilePath: "var/lib/chisel/manifest.wall",
						Packages: []types.Package{
							{
								ID:      "base-files@13ubuntu10.1",
								Name:    "base-files",
								Version: "13ubuntu10.1",
								Arch:    "arm64",
								Digest:  digest.NewDigestFromString(digest.SHA256, "736e4aff26d71c9f4dce7a9fed88144797211f8f18ff4210b9da977d91ee3b32"),
								InstalledFiles: []string{
									"/var/lib/chisel/manifest.wall",
									"/usr/share/doc/base-files/copyright",
									"/lib",
									"/usr/lib/",
									"/run/",
									"/var/cache/",
									"/var/lib/",
									"/var/log/",
									"/var/run",
									"/var/tmp/",
								},
							},
							{
								ID:      "libc6@2.39-0ubuntu8.3",
								Name:    "libc6",
								Version: "2.39",
								Release: "0ubuntu8.3",
								Arch:    "arm64",
								Digest:  digest.NewDigestFromString(digest.SHA256, "d43cc7556a5e005e341475462ad5a257d095729c52a1c99341c27235895da8a6"),
								InstalledFiles: []string{
									"/usr/share/doc/libc6/copyright",
									"/usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1",
									"/usr/lib/aarch64-linux-gnu/libBrokenLocale.so.1",
									"/usr/lib/aarch64-linux-gnu/libanl.so.1",
									"/usr/lib/aarch64-linux-gnu/libc.so.6",
									"/usr/lib/aarch64-linux-gnu/libc_malloc_debug.so.0",
									"/usr/lib/aarch64-linux-gnu/libdl.so.2",
									"/usr/lib/aarch64-linux-gnu/libm.so.6",
									"/usr/lib/aarch64-linux-gnu/libmemusage.so",
									"/usr/lib/aarch64-linux-gnu/libmvec.so.1",
									"/usr/lib/aarch64-linux-gnu/libnsl.so.1",
									"/usr/lib/aarch64-linux-gnu/libnss_compat.so.2",
									"/usr/lib/aarch64-linux-gnu/libnss_dns.so.2",
									"/usr/lib/aarch64-linux-gnu/libnss_files.so.2",
									"/usr/lib/aarch64-linux-gnu/libnss_hesiod.so.2",
									"/usr/lib/aarch64-linux-gnu/libpcprofile.so",
									"/usr/lib/aarch64-linux-gnu/libpthread.so.0",
									"/usr/lib/aarch64-linux-gnu/libresolv.so.2",
									"/usr/lib/aarch64-linux-gnu/librt.so.1",
									"/usr/lib/aarch64-linux-gnu/libthread_db.so.1",
									"/usr/lib/aarch64-linux-gnu/libutil.so.1",
									"/usr/lib/ld-linux-aarch64.so.1",
								},
							},
						},
					},
				},
			},
		},
		{
			name:      "librdkafka1",
			testFiles: map[string]string{"./testdata/librdkafka1.manifest.wall": "var/lib/chisel/manifest.wall"},
			want: &analyzer.AnalysisResult{
				OS: types.OS{Family: types.Ubuntu},
				PackageInfos: []types.PackageInfo{
					{
						FilePath: "var/lib/chisel/manifest.wall",
						Packages: []types.Package{
							{
								ID:      "base-files@13ubuntu10.1",
								Name:    "base-files",
								Version: "13ubuntu10.1",
								Arch:    "amd64",
								Digest:  digest.NewDigestFromString(digest.SHA256, "436e9c5b675487852d577fde1eacda19025c14fc13e0f268ec7c2d837d939447"),
								InstalledFiles: []string{
									"/var/lib/chisel/manifest.wall",
									"/usr/share/doc/base-files/copyright",
									"/lib",
									"/lib64",
									"/usr/lib/",
									"/usr/lib64/",
									"/run/",
									"/var/cache/",
									"/var/lib/",
									"/var/log/",
									"/var/run",
									"/var/tmp/",
								},
							},
							{
								ID:      "libc6@2.39-0ubuntu8.3",
								Name:    "libc6",
								Version: "2.39",
								Release: "0ubuntu8.3",
								Arch:    "amd64",
								Digest:  digest.NewDigestFromString(digest.SHA256, "84cd7925cb7773471f09810cbebcd796f2fd33a07cb761a64116eeb7b9096a2f"),
								InstalledFiles: []string{
									"/usr/share/doc/libc6/copyright",
									"/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
									"/usr/lib/x86_64-linux-gnu/libBrokenLocale.so.1",
									"/usr/lib/x86_64-linux-gnu/libanl.so.1",
									"/usr/lib/x86_64-linux-gnu/libc.so.6",
									"/usr/lib/x86_64-linux-gnu/libc_malloc_debug.so.0",
									"/usr/lib/x86_64-linux-gnu/libdl.so.2",
									"/usr/lib/x86_64-linux-gnu/libm.so.6",
									"/usr/lib/x86_64-linux-gnu/libmemusage.so",
									"/usr/lib/x86_64-linux-gnu/libmvec.so.1",
									"/usr/lib/x86_64-linux-gnu/libnsl.so.1",
									"/usr/lib/x86_64-linux-gnu/libnss_compat.so.2",
									"/usr/lib/x86_64-linux-gnu/libnss_dns.so.2",
									"/usr/lib/x86_64-linux-gnu/libnss_files.so.2",
									"/usr/lib/x86_64-linux-gnu/libnss_hesiod.so.2",
									"/usr/lib/x86_64-linux-gnu/libpcprofile.so",
									"/usr/lib/x86_64-linux-gnu/libpthread.so.0",
									"/usr/lib/x86_64-linux-gnu/libresolv.so.2",
									"/usr/lib/x86_64-linux-gnu/librt.so.1",
									"/usr/lib/x86_64-linux-gnu/libthread_db.so.1",
									"/usr/lib/x86_64-linux-gnu/libutil.so.1",
									"/usr/lib64/ld-linux-x86-64.so.2",
								},
							},
							{
								ID:      "libdb5.3t64@5.3.28+dfsg2-7",
								Name:    "libdb5.3t64",
								Version: "5.3.28+dfsg2",
								Release: "7",
								Arch:    "amd64",
								Digest:  digest.NewDigestFromString(digest.SHA256, "a78a25c8fad8fdd0b7bc6b297da5d5685579be1e57732aa47870830e4a13161e"),
								InstalledFiles: []string{
									"/usr/share/doc/libdb5.3t64/copyright",
									"/usr/lib/x86_64-linux-gnu/libdb-5.3.so",
								},
							},
							{
								ID:      "liblz4-1@1.9.4-1build1.1",
								Name:    "liblz4-1",
								Version: "1.9.4",
								Release: "1build1.1",
								Arch:    "amd64",
								Digest:  digest.NewDigestFromString(digest.SHA256, "319331270d5cc52d5ebffe51c941d7b01b432bc402c2924b557209a64d4ecbad"),
								InstalledFiles: []string{
									"/usr/share/doc/liblz4-1/copyright",
									"/usr/lib/x86_64-linux-gnu/liblz4.so.1",
									"/usr/lib/x86_64-linux-gnu/liblz4.so.1.9.4",
								},
							},
							{
								ID:      "librdkafka1@2.3.0-1build2",
								Name:    "librdkafka1",
								Version: "2.3.0",
								Release: "1build2",
								Arch:    "amd64",
								Digest:  digest.NewDigestFromString(digest.SHA256, "0294972c1eb7229644ba09c97772b69d0587686b1e082d75ea8d77d615385a2b"),
								InstalledFiles: []string{
									"/usr/share/doc/librdkafka1/copyright",
									"/usr/lib/x86_64-linux-gnu/librdkafka.so.1",
								},
							},
							{
								ID:      "libsasl2-2@2.1.28+dfsg1-5ubuntu3.1",
								Name:    "libsasl2-2",
								Version: "2.1.28+dfsg1",
								Release: "5ubuntu3.1",
								Arch:    "amd64",
								Digest:  digest.NewDigestFromString(digest.SHA256, "eda097f98dcb3a08b9ce157d6191d140e4885c1cba47b683c94b8ca45e88f458"),
								InstalledFiles: []string{
									"/usr/share/doc/libsasl2-2/copyright",
									"/usr/lib/x86_64-linux-gnu/libsasl2.so.2",
									"/usr/lib/x86_64-linux-gnu/libsasl2.so.2.0.25",
								},
							},
							{
								ID:      "libsasl2-modules-db@2.1.28+dfsg1-5ubuntu3.1",
								Name:    "libsasl2-modules-db",
								Version: "2.1.28+dfsg1",
								Release: "5ubuntu3.1",
								Arch:    "amd64",
								Digest:  digest.NewDigestFromString(digest.SHA256, "1f13548b1774cd9c70c50b8c3267204a101334a4d2f979338896ba5a4c6f81b8"),
								InstalledFiles: []string{
									"/usr/share/doc/libsasl2-modules-db/copyright",
									"/usr/lib/x86_64-linux-gnu/sasl2/libsasldb.so",
									"/usr/lib/x86_64-linux-gnu/sasl2/libsasldb.so.2",
									"/usr/lib/x86_64-linux-gnu/sasl2/libsasldb.so.2.0.25",
								},
							},
							{
								ID:      "libssl3t64@3.0.13-0ubuntu3.4",
								Name:    "libssl3t64",
								Version: "3.0.13",
								Release: "0ubuntu3.4",
								Arch:    "amd64",
								Digest:  digest.NewDigestFromString(digest.SHA256, "460131a068304561137c0447b6710438a80945202336f86f28ffab6891b1d1f1"),
								InstalledFiles: []string{
									"/usr/share/doc/libssl3t64/copyright",
									"/usr/lib/x86_64-linux-gnu/engines-3/afalg.so",
									"/usr/lib/x86_64-linux-gnu/engines-3/loader_attic.so",
									"/usr/lib/x86_64-linux-gnu/engines-3/padlock.so",
									"/usr/lib/x86_64-linux-gnu/libcrypto.so.3",
									"/usr/lib/x86_64-linux-gnu/libssl.so.3",
									"/usr/lib/x86_64-linux-gnu/ossl-modules/legacy.so",
								},
							},
							{
								ID:      "libzstd1@1.5.5+dfsg2-2build1.1",
								Name:    "libzstd1",
								Version: "1.5.5+dfsg2",
								Release: "2build1.1",
								Arch:    "amd64",
								Digest:  digest.NewDigestFromString(digest.SHA256, "dfcf25061e07aad7efd3f4f880ba5ad4d4d09ebe7fc8cc77ab6b8a161d6d4727"),
								InstalledFiles: []string{
									"/usr/share/doc/libzstd1/copyright",
									"/usr/lib/x86_64-linux-gnu/libzstd.so.1",
									"/usr/lib/x86_64-linux-gnu/libzstd.so.1.5.5",
								},
							},
							{
								ID:      "zlib1g@1:1.3.dfsg-3.1ubuntu2.1",
								Name:    "zlib1g",
								Version: "1.3.dfsg",
								Release: "3.1ubuntu2.1",
								Epoch:   1,
								Arch:    "amd64",
								Digest:  digest.NewDigestFromString(digest.SHA256, "7074b6a2f6367a10d280c00a1cb02e74277709180bab4f2491a2f355ab2d6c20"),
								InstalledFiles: []string{
									"/usr/share/doc/zlib1g/copyright",
									"/usr/lib/x86_64-linux-gnu/libz.so.1",
									"/usr/lib/x86_64-linux-gnu/libz.so.1.3",
								},
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := newChiselPkgAnalyzer(analyzer.AnalyzerOptions{})
			require.NoError(t, err)
			ctx := context.Background()

			mfs := mapfs.New()
			for testPath, osPath := range tt.testFiles {
				err = mfs.MkdirAll(filepath.Dir(osPath), os.ModePerm)
				require.NoError(t, err)

				// Chisel manifests are zstd compressed, here in order to avoid having a binary compressed
				// testfile, we keep the test manifest files uncompressed and only compress them for
				// the tests
				func() {
					testFile, err := os.Open(testPath)
					require.NoError(t, err)
					defer testFile.Close()

					compressor, err := zstd.NewWriter(nil)
					require.NoError(t, err)
					defer compressor.Close()

					testFileBytes, err := io.ReadAll(testFile)
					require.NoError(t, err)
					compressedData := compressor.EncodeAll(testFileBytes, []byte{})

					err = mfs.WriteVirtualFile(osPath, compressedData, fs.ModePerm)
					require.NoError(t, err)
				}()
			}

			got, err := a.PostAnalyze(ctx, analyzer.PostAnalysisInput{
				FS: mfs,
			})
			require.NoError(t, err)

			// Sort the result for consistency
			for i := range got.PackageInfos {
				sort.Sort(got.PackageInfos[i].Packages)
			}

			assert.Equal(t, tt.want, got)
		})
	}
}
