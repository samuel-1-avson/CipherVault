class Ciphervault < Formula
  desc "Decentralized, zero-knowledge encrypted version control for confidential files"
  homepage "https://github.com/samuel-1-avson/CipherVault"
  version "1.0.17"
  license "MIT OR Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.17/ciphervault-v1.0.17-aarch64-apple-darwin.tar.gz"
      sha256 "6a59791dbf8493dd7def98880bc62b1c2ade0464bd6a6363861a527f8b76bf69"
    else
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.17/ciphervault-v1.0.17-x86_64-apple-darwin.tar.gz"
      sha256 "16696dc5f94bc604a550c7cd0291ef9282614b48693674278be08b558de52bb5"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.17/ciphervault-v1.0.17-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "17629ed7d1e0b2d2099c1745168f12ee7c83759f2273363d7e8717d11e1227fd"
    else
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.17/ciphervault-v1.0.17-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "7353fabe4b8bf857fff87696daf33ace31634993f0ff9c97f77322607c98175c"
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
