package validation

import (
    "fmt"
    "os"
    "strings"
    "strconv"
    "bufio"
)

// CgroupValidation holds validation results
type CgroupValidation struct {
    Available bool
    Version   int
    Errors    []string
    Stats     map[string]string
    Permissions map[string]bool
    MountPoints map[string]string
}

func ValidateCgroups() *CgroupValidation {
    v := &CgroupValidation{
        Stats: make(map[string]string, 10),
        Errors: make([]string, 0, 10),
        Permissions: make(map[string]bool, 3),
        MountPoints: make(map[string]string, 5),
    }

    // Check if /sys/fs/cgroup exists and validate permissions
    if info, err := os.Stat("/sys/fs/cgroup"); err != nil {
        v.Errors = append(v.Errors, fmt.Sprintf("cgroup fs not found: %v", err))
        return v
    } else {
        v.Permissions["read"] = info.Mode()&0444 != 0
        v.Permissions["write"] = info.Mode()&0222 != 0
        v.Permissions["execute"] = info.Mode()&0111 != 0
    }

    // Check mount points
    if out, err := os.ReadFile("/proc/mounts"); err == nil {
        for _, line := range strings.Split(string(out), "\n") {
            fields := strings.Fields(line)
            if len(fields) >= 2 && strings.Contains(fields[1], "cgroup") {
                v.MountPoints[fields[1]] = fields[0]
            }
        }
    }

    // Detect version
    if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err == nil {
        v.Version = 2
    } else if _, err := os.Stat("/sys/fs/cgroup/cpu"); err == nil {
        v.Version = 1
    }

    // Read key stats for validation
    files := []string{
        "cpu.stat",
        "memory.current",
        "io.stat",
    }

    for _, file := range files {
        path := fmt.Sprintf("/sys/fs/cgroup/%s", file)
        content, err := os.ReadFile(path)
        if err != nil {
            v.Errors = append(v.Errors, fmt.Sprintf("cannot read %s: %v", file, err))
            continue
        }
        v.Stats[file] = string(content)
    }

    // Check process cgroup
    if content, err := os.ReadFile("/proc/self/cgroup"); err == nil {
        v.Stats["self_cgroup"] = string(content)
    } else {
        v.Errors = append(v.Errors, fmt.Sprintf("cannot read process cgroup: %v", err))
    }

    v.Available = v.Version > 0 && len(v.Errors) == 0
    return v
}

// ParseCPUStat parses cpu.stat and returns usage in microseconds
func ParseCPUStat(content string) (uint64, error) {
    scanner := bufio.NewScanner(strings.NewReader(content))
    for scanner.Scan() {
        fields := strings.Fields(scanner.Text())
        if len(fields) == 2 && fields[0] == "usage_usec" {
            return strconv.ParseUint(fields[1], 10, 64)
        }
    }
    return 0, fmt.Errorf("usage_usec not found in cpu.stat")
}

// ParseMemoryCurrent parses memory.current
func ParseMemoryCurrent(content string) (uint64, error) {
    return strconv.ParseUint(strings.TrimSpace(content), 10, 64)
}

// ParseMemoryStats parses memory.stat for detailed memory metrics
func ParseMemoryStats(content string) (map[string]uint64, error) {
    stats := make(map[string]uint64)
    scanner := bufio.NewScanner(strings.NewReader(content))
    for scanner.Scan() {
        fields := strings.Fields(scanner.Text())
        if len(fields) == 2 {
            if val, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
                stats[fields[0]] = val
            }
        }
    }
    return stats, scanner.Err()
}

// ParseIOStat parses io.stat for block I/O statistics
func ParseIOStat(content string) (map[string]map[string]uint64, error) {
    stats := make(map[string]map[string]uint64)
    scanner := bufio.NewScanner(strings.NewReader(content))
    for scanner.Scan() {
        fields := strings.Fields(scanner.Text())
        if len(fields) < 2 {
            continue
        }
        
        device := fields[0]
        stats[device] = make(map[string]uint64)
        
        for i := 1; i < len(fields); i++ {
            kv := strings.Split(fields[i], "=")
            if len(kv) == 2 {
                if val, err := strconv.ParseUint(kv[1], 10, 64); err == nil {
                    stats[device][kv[0]] = val
                }
            }
        }
    }
    return stats, scanner.Err()
}
