class Ciphervault < Formula
  desc "Decentralized, zero-knowledge encrypted version control for confidential files"
  homepage "https://github.com/samuel-1-avson/CipherVault"
  version "1.0.12"
  license "MIT OR Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.12/ciphervault-v1.0.12-aarch64-apple-darwin.tar.gz"
      sha256 "b56b3921ec599783b675d3187117d25b6798247eb416d5e0d689456abe75e540"
    else
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.12/ciphervault-v1.0.12-x86_64-apple-darwin.tar.gz"
      sha256 "29ca4c7890c3a96662ed138070e5c2a4b0ecf2e4e83113c6c334d98d2767b4d3"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.12/ciphervault-v1.0.12-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "2d395aa735ef6b8336e1540c196ddbb94f714798ddcc99235640b2e5b9edf1df"
    else
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.12/ciphervault-v1.0.12-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "91f49fbb00855dca4e4c116c7940711fe2ff2b9236524d73e34aca5bd185db6e"
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
