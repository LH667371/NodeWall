package geoip

import (
	"compress/gzip"
	"encoding/csv"
	"fmt"
	"io"
	"net/netip"
	"os"
	"sort"
	"strings"

	"nodewall/internal/models"
)

type CountryDB struct {
	ranges []countryRange
}

type countryRange struct {
	start uint32
	end   uint32
	geo   models.GeoLocation
}

func LoadCountryDB(path string) (*CountryDB, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, nil
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var reader io.Reader = file
	if strings.HasSuffix(strings.ToLower(path), ".gz") {
		gzReader, err := gzip.NewReader(file)
		if err != nil {
			return nil, err
		}
		defer gzReader.Close()
		reader = gzReader
	}

	csvReader := csv.NewReader(reader)
	csvReader.FieldsPerRecord = -1
	csvReader.ReuseRecord = true

	ranges := make([]countryRange, 0, 300000)
	for {
		record, err := csvReader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read geoip csv: %w", err)
		}
		if len(record) < 7 {
			continue
		}

		startAddr, err := netip.ParseAddr(strings.TrimSpace(record[0]))
		if err != nil || !startAddr.Is4() {
			continue
		}
		endAddr, err := netip.ParseAddr(strings.TrimSpace(record[1]))
		if err != nil || !endAddr.Is4() {
			continue
		}

		ranges = append(ranges, countryRange{
			start: ipv4ToUint32(startAddr),
			end:   ipv4ToUint32(endAddr),
			geo: models.GeoLocation{
				ContinentCode: strings.TrimSpace(record[2]),
				ContinentName: strings.TrimSpace(record[3]),
				CountryCode:   strings.TrimSpace(record[4]),
				CountryName:   strings.TrimSpace(record[6]),
			},
		})
	}

	sort.Slice(ranges, func(i, j int) bool { return ranges[i].start < ranges[j].start })
	return &CountryDB{ranges: ranges}, nil
}

func (db *CountryDB) Lookup(addr netip.Addr) (models.GeoLocation, bool) {
	if db == nil || !addr.Is4() || len(db.ranges) == 0 {
		return models.GeoLocation{}, false
	}

	target := ipv4ToUint32(addr)
	index := sort.Search(len(db.ranges), func(i int) bool {
		return db.ranges[i].start > target
	})
	if index == 0 {
		return models.GeoLocation{}, false
	}

	item := db.ranges[index-1]
	if target < item.start || target > item.end {
		return models.GeoLocation{}, false
	}
	return item.geo, true
}

func ipv4ToUint32(addr netip.Addr) uint32 {
	bytes := addr.As4()
	return uint32(bytes[0])<<24 | uint32(bytes[1])<<16 | uint32(bytes[2])<<8 | uint32(bytes[3])
}
