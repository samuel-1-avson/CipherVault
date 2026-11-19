class Ciphervault < Formula
  desc "Decentralized, zero-knowledge encrypted version control for confidential files"
  homepage "https://github.com/samuel-1-avson/CipherVault"
  version "1.0.37"
  license "MIT OR Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.37/ciphervault-v1.0.37-aarch64-apple-darwin.tar.gz"
      sha256 "1a6b8b1b17068fbaca505b5924ddcf031362c91ed9253ebf8f9ed53a7ec6db99"
    else
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.37/ciphervault-v1.0.37-x86_64-apple-darwin.tar.gz"
      sha256 "74a0305f5c960af52b617e956453d2a9506d937f432451a9e94c7f1a8ab3c654"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.37/ciphervault-v1.0.37-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "0888f755a146e444b919e5c70458b001de3779487820cf277b18fb1cbc98a5a0"
    else
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.37/ciphervault-v1.0.37-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "f13d0eae8beb8054a7d1c53c925831357e22463b0078c230c54b7d3b891227b3"
    end
  end

  def install
    bin.install "bin/ciphervault"
    bin.install "bin/cv"
    bin.install "bin/ciphervault-operator"
    bin.install "bin/ciphervault-agent"
    bin.install "bin/ciphervault-maintenance"

    if Dir.exist?("config")
      (etc/"ciphervault").install Dir["config/*"]
    end
  end

  def caveats
    <<~EOS
      Quick Start (cv and ciphervault are the same tool):
        cv init
        cv track .env
        cv push -m "Initial commit"
        cv diff
        cv run -- npm start
        cv peers
    EOS
  end

  test do
    assert_match "Decentralized, encrypted version control", shell_output("#{bin}/ciphervault --help")
    assert_match "cv node setup", shell_output("#{bin}/cv --help")
  end
end
