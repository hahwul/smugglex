CARGO_TOML   = "Cargo.toml"
CARGO_LOCK   = "Cargo.lock"
FLAKE_NIX    = "flake.nix"
SNAP_YAML    = "snap/snapcraft.yaml"
AUR_PKGBUILD = "aur/PKGBUILD"

def cargo_toml_version : String?
  content = File.read(CARGO_TOML)
  pkg = content.match(/^\[package\][\s\S]*?(?=^\[|\z)/m)
  return nil unless pkg
  match = pkg[0].match(/^version\s*=\s*"([^"]+)"/m)
  match ? match[1] : nil
rescue
  nil
end

def cargo_lock_version : String?
  content = File.read(CARGO_LOCK)
  match = content.match(/name\s*=\s*"smugglex"\s*\nversion\s*=\s*"([^"]+)"/)
  match ? match[1] : nil
rescue
  nil
end

def flake_version : String?
  content = File.read(FLAKE_NIX)
  match = content.match(/version\s*=\s*"([^"]+)"\s*;/)
  match ? match[1] : nil
rescue
  nil
end

def snap_version : String?
  content = File.read(SNAP_YAML)
  match = content.match(/^version:\s*['"]?v?([^'"\s]+)['"]?\s*$/m)
  match ? match[1] : nil
rescue
  nil
end

def aur_version : String?
  content = File.read(AUR_PKGBUILD)
  match = content.match(/^pkgver=([^\s]+)/m)
  match ? match[1].gsub('_', '-') : nil
rescue
  nil
end
