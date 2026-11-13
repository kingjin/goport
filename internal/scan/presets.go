package scan

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

// gobyPresets mirrors the port presets shipped in Goby's config/config.json so a
// GoPort scan can be expressed with the same vocabulary ("enterprise", "minimal",
// "iot", ...). "U:" marks a UDP port exactly like Goby does.
var gobyPresets = map[string]string{
	"minimal":    "21,22,80,U:137,U:161,443,445,U:1900,3306,3389,U:5353,8080",
	"enterprise": "21,22,23,25,53,U:53,U:69,80,81,U:88,110,111,U:111,123,U:123,135,U:137,139,U:161,U:177,389,U:427,443,445,465,500,515,U:520,U:523,548,623,U:626,636,873,902,1080,1099,1433,U:1434,1521,U:1604,U:1645,U:1701,1883,U:1900,2049,2181,2375,2379,U:2425,3128,3306,3389,4730,U:5060,5222,U:5351,U:5353,5432,5555,5601,5672,U:5683,5900,5938,5984,6000,6379,7001,7077,8080,8081,8443,8545,8686,9000,9001,9042,9092,9100,9200,9418,9999,11211,U:11211,27017,U:33848,37777,50000,50070,61616",
	"cafe":       "21,22,23,25,U:53,80,110,111,U:111,135,U:137,139,U:161,389,443,445,515,548,873,902,1080,1433,U:1434,U:1900,2181,2375,2379,3128,3306,3389,U:5060,5222,U:5351,U:5353,5555,5672,U:5683,5900,6379,7001,8080,9000,9100,9200,11211,U:11211,U:37810",
	"database":   "U:523,1433,U:1434,1521,1583,2100,2049,U:2638,3050,3306,3351,5000,5432,5433,5601,5984,6082,6379,7474,8080,8088,8089,8098,8471,9000,9160,9200,9300,9471,11211,U:11211,15672,19888,27017,27019,27080,28017,50000,50070,50090",
	"general":    "1,7,9,13,19,21-23,25,37,42,49,53,69,79-81,85,105,109-111,113,123,135,137-139,143,161,179,222,264,384,389,402,407,443-446,465,500,502,512-515,523-524,540,548,554,587,617,623,689,705,771,783,873,888,902,910,912,921,993,995,998,1000,1024,1030,1035,1090,1098-1103,1128-1129,1158,1199,1211,1220,1234,1241,1300,1311,1352,1433-1435,1440,1494,1521,1530,1533,1581-1582,1604,1720,1723,1755,1811,1900,2000-2001,2049,2082,2083,2100,2103,2121,2199,2207,2222,2323,2362,2375,2380-2381,2525,2533,2598,2601,2604,2638,2809,2947,2967,3000,3037,3050,3057,3128,3200,3217,3273,3299,3306,3311,3312,3389,3460,3500,3628,3632,3690,3780,3790,3817,4000,4322,4433,4444-4445,4659,4679,4848,5000,5038,5040,5051,5060-5061,5093,5168,5247,5250,5351,5353,5355,5400,5405,5432-5433,5498,5520-5521,5554-5555,5560,5580,5601,5631-5632,5666,5800,5814,5900-5910,5920,5984-5986,6000,6050,6060,6070,6080,6082,6101,6106,6112,6262,6379,6405,6502-6504,6542,6660-6661,6667,6905,6988,7001,7021,7071,7080,7144,7181,7210,7443,7510,7579-7580,7700,7770,7777-7778,7787,7800-7801,7879,7902,8000-8001,8008,8014,8020,8023,8028,8030,8080-8082,8087,8090,8095,8161,8180,8205,8222,8300,8303,8333,8400,8443-8444,8503,8800,8812,8834,8880,8888-8890,8899,8901-8903,9000,9002,9060,9080-9081,9084,9090,9099-9100,9111,9152,9200,9390-9391,9443,9495,9809-9815,9855,9999-10001,10008,10050-10051,10080,10098,10162,10202-10203,10443,10616,10628,11000,11099,11211,11234,11333,12174,12203,12221,12345,12397,12401,13364,13500,13838,14330,15200,16102,17185,17200,18881,19300,19810,20010,20031,20034,20101,20111,20171,20222,22222,23472,23791,23943,25000,25025,26000,26122,27000,27017,27888,28222,28784,30000,30718,31001,31099,32764,32913,34205,34443,37718,38080,38292,40007,41025,41080,41523-41524,44334,44818,45230,46823-46824,47001-47002,48899,49152,50000-50004,50013,50500-50504,52302,55553,57772,62078,62514,65535",
	"scada":      "21,22,23,80,102,U:161,443,502,1089-1091,U:2222,U:3671,4000,U:4000,4840,U:5050,U:9600,20000,U:20000,U:47808,34962-34964,U:34980,44818,U:44818,U:55000-55003",
	"iot":        "21,22,23,25,80,81,82,83,84,88,137,143,443,445,554,631,1080,1883,1900,2000,2323,U:3671,U:3702,4433,4443,4567,5222,5683,7474,7547,8000,8023,8080,8081,8443,8088,U:8600,8883,8888,9000,9090,9999,10000,U:30718,U:37020,37777,U:37810,49152",
	"backdoor":   "50050,U:53413",
	"all":        "0-65535",
}

// presetAliases maps the friendly names a user is likely to type onto the
// canonical Goby preset keys.
var presetAliases = map[string]string{
	"min":            "minimal",
	"default":        "minimal",
	"ent":            "enterprise",
	"coffee":         "cafe",
	"hotel":          "cafe",
	"airport":        "cafe",
	"db":             "database",
	"ics":            "scada",
	"ot":             "scada",
	"backdoors":      "backdoor",
	"backdoor check": "backdoor",
	"full":           "all",
	"0-65535":        "all",
}

// PresetNames returns the sorted preset names, for help output.
func PresetNames() []string {
	names := make([]string, 0, len(gobyPresets))
	for k := range gobyPresets {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

// LookupPreset resolves a preset name (case-insensitive, with aliases) to its
// raw port specification.
func LookupPreset(name string) (spec string, ok bool) {
	k := strings.ToLower(strings.TrimSpace(name))
	if alias, found := presetAliases[k]; found {
		k = alias
	}
	spec, ok = gobyPresets[k]
	return spec, ok
}

// LoadGobyPresets reads the port presets out of a Goby installation's
// config/config.json, so GoPort can reuse a customized Goby port list.
func LoadGobyPresets(path string) (map[string]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取 Goby 配置失败：%w", err)
	}
	var cfg struct {
		Ports []struct {
			Title string `json:"title"`
			Value string `json:"value"`
		} `json:"ports"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("解析 Goby 配置失败：%w", err)
	}
	if len(cfg.Ports) == 0 {
		return nil, fmt.Errorf("%s 中没有 ports 预设", path)
	}
	out := make(map[string]string, len(cfg.Ports))
	for _, p := range cfg.Ports {
		title := strings.TrimSpace(p.Title)
		if title == "" || strings.TrimSpace(p.Value) == "" {
			continue
		}
		key := strings.ToLower(title)
		key = strings.TrimPrefix(key, "scanconfig.")
		key = strings.ReplaceAll(key, " ", "")
		key = strings.ReplaceAll(key, "/", "-")
		out[key] = p.Value
	}
	return out, nil
}
