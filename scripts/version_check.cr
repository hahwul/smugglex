# Reports the version string declared in each file smugglex keeps in lockstep
# (Cargo.toml, Cargo.lock, flake.nix, snap/snapcraft.yaml, aur/PKGBUILD).
# Exits non-zero when they disagree so it can gate a release.

require "./version_helpers"

cargo_v = cargo_toml_version
lock_v  = cargo_lock_version
flake_v = flake_version
snap_v  = snap_version
aur_v   = aur_version

puts "#{CARGO_TOML.ljust(22)} #{cargo_v || "Not found"}"
puts "#{CARGO_LOCK.ljust(22)} #{lock_v || "Not found"}"
puts "#{FLAKE_NIX.ljust(22)} #{flake_v || "Not found"}"
puts "#{SNAP_YAML.ljust(22)} #{snap_v || "Not found"}"
puts "#{AUR_PKGBUILD.ljust(22)} #{aur_v || "Not found"}"
puts

versions = [cargo_v, lock_v, flake_v, snap_v, aur_v].compact

if versions.empty?
  puts "No versions found!"
  exit 1
end

unique = versions.uniq

if unique.size == 1
  puts "All versions match: #{unique.first}"
else
  puts "Versions disagree: #{unique.join(", ")}"
  exit 1
end
