package chisel

import (
	"context"
	"fmt"
	"os"

	"github.com/canonical/chisel/public/jsonwall"
	"github.com/klauspost/compress/zstd"
	debVersion "github.com/knqyf263/go-deb-version"

	"github.com/aquasecurity/trivy/pkg/digest"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
)

func init() {
	analyzer.RegisterPostAnalyzer(analyzer.TypeChisel, newChiselPkgAnalyzer)
}

const (
	analyzerVersion    = 1
	chiselManifestFile = "var/lib/chisel/manifest.wall"
)

type chiselPkgAnalyzer struct {
	logger *log.Logger
}

type ChiselPackage struct {
	Kind    string `json:"kind"`
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
	Digest  string `json:"sha256,omitempty"`
	Arch    string `json:"arch,omitempty"`
}

type ChiselContent struct {
	Kind  string `json:"kind"`
	Slice string `json:"slice,omitempty"`
	Path  string `json:"path,omitempty"`
}

func newChiselPkgAnalyzer(_ analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	return &chiselPkgAnalyzer{
		logger: log.WithPrefix("chisel"),
	}, nil
}

func (a chiselPkgAnalyzer) PostAnalyze(ctx context.Context, input analyzer.PostAnalysisInput) (*analyzer.AnalysisResult, error) {
	db, err := loadManifest(chiselManifestFile, input)
	if err != nil {
		return nil, err
	}

	packages, err := a.getPackages(db)
	if err != nil {
		return nil, err
	}

	return &analyzer.AnalysisResult{
		OS: types.OS{
			Family: types.Ubuntu,
		},
		PackageInfos: []types.PackageInfo{
			{
				FilePath: chiselManifestFile,
				Packages: packages,
			},
		},
	}, nil
}

func (a chiselPkgAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return filePath == chiselManifestFile
}

func (a chiselPkgAnalyzer) Type() analyzer.Type {
	return analyzer.TypeChisel
}

func (a chiselPkgAnalyzer) Version() int {
	return analyzerVersion
}

func loadManifest(manifestPath string, input analyzer.PostAnalysisInput) (*jsonwall.DB, error) {
	compressedManifest, err := input.FS.Open(manifestPath)
	if err != nil {
		return nil, err
	}

	manifest, err := zstd.NewReader(compressedManifest)
	if err != nil {
		return nil, err
	}

	db, err := jsonwall.ReadDB(manifest)
	if err != nil {
		return nil, err
	}

	return db, nil
}

func (a chiselPkgAnalyzer) getPackages(db *jsonwall.DB) (packages []types.Package, err error) {
	packagesIterator, err := db.Iterate(&ChiselPackage{Kind: "package"})
	if err != nil {
		return nil, err
	}

	for packagesIterator.Next() {
		var chiselPackage ChiselPackage
		if err := packagesIterator.Get(&chiselPackage); err != nil {
			return nil, err
		}

		pkg := types.Package{
			Name:    chiselPackage.Name,
			Version: chiselPackage.Version,
			Arch:    chiselPackage.Arch,
			Digest:  digest.NewDigestFromString(digest.SHA256, chiselPackage.Digest),
		}

		installedFiles, err := getInstalledFiles(db, pkg.Name)
		if err != nil {
			return nil, err
		}

		pkg.InstalledFiles = installedFiles

		if err := a.setVersion(&pkg); err != nil {
			return nil, err
		}

		packages = append(packages, pkg)
	}

	return packages, nil
}

func getInstalledFiles(db *jsonwall.DB, pkg string) (installedFiles []string, err error) {
	contentsIterator, err := db.IteratePrefix(&ChiselContent{Kind: "content", Slice: pkg})
	if err != nil {
		return nil, err
	}

	for contentsIterator.Next() {
		var content ChiselContent
		if err := contentsIterator.Get(&content); err != nil {
			return nil, err
		}
		installedFiles = append(installedFiles, content.Path)
	}

	return installedFiles, nil
}

func (a chiselPkgAnalyzer) setVersion(pkg *types.Package) error {
	pkgVersion := pkg.Version
	v, err := debVersion.NewVersion(pkgVersion)
	if err != nil {
		return err
	}

	pkg.ID = fmt.Sprintf("%s@%s", pkg.Name, pkg.Version)
	pkg.Version = v.Version()
	pkg.Epoch = v.Epoch()
	pkg.Release = v.Revision()

	if pkg.SrcName == "" {
		pkg.SrcName = pkg.Name
	}
	if pkg.SrcVersion == "" {
		pkg.SrcVersion = pkgVersion
	}

	if v, err := debVersion.NewVersion(pkg.SrcVersion); err != nil {
		a.logger.Warn("Invalid source version", log.String("OS", "ubuntu"),
			log.String("package", pkg.Name), log.String("version", pkg.SrcVersion))
		return nil
	} else {
		pkg.SrcVersion = v.Version()
		pkg.SrcEpoch = v.Epoch()
		pkg.SrcRelease = v.Revision()
	}

	return nil
}
