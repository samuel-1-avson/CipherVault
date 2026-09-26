class Ciphervault < Formula
  desc "Decentralized, zero-knowledge encrypted version control for confidential files"
  homepage "https://github.com/samuel-1-avson/CipherVault"
  version "1.0.17"
  license "MIT OR Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.17/ciphervault-v1.0.17-aarch64-apple-darwin.tar.gz"
      sha256 "7b08539eb7d7e1cf949b06e9f5001c0b3b544479c20349e3df3e01828457263c"
    else
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.17/ciphervault-v1.0.17-x86_64-apple-darwin.tar.gz"
      sha256 "dc4fa92ac2b45f5c761bfaa218d832ce9c83c51febdcb439e8c392ee8f15b7dd"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.17/ciphervault-v1.0.17-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "a791532d1ad20d934554ca9575ea41d975ee80990b3c8eceaa1cee642db3bc48"
    else
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.17/ciphervault-v1.0.17-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "9c4db4e2882b1f3d412c0cbad565beed42d7f15b6dff6ff4947446677cc6eecc"
    end
  end

  def install
    bin.install "bin/ciphervault"
    bin.install "bin/ciphervault-operator"
    bin.install "bin/ciphervault-agent"
    bin.install "bin/ciphervault-maintenance"

    if Dir.exist?("config")
      (etc/"ciphervault").install Dir["config/*"]
    end
  end

  def caveats
    <<~EOS
      Quick Start:
        ciphervault init
        ciphervault track .env
        ciphervault push -m "Initial commit"
        ciphervault diff
        ciphervault run -- npm start
        ciphervault peers
    EOS
  end

  test do
    assert_match "Decentralized, encrypted version control", shell_output("#{bin}/ciphervault --help")
  end
end
