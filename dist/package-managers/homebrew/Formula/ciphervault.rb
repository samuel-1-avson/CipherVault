class Ciphervault < Formula
  desc "Decentralized, zero-knowledge encrypted version control for confidential files"
  homepage "https://github.com/samuel-1-avson/CipherVault"
  version "1.0.22"
  license "MIT OR Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.22/ciphervault-v1.0.22-aarch64-apple-darwin.tar.gz"
      sha256 "1116e354391ab0c5464d42d408cc40a70e64470db97a597bc7f1955873c97029"
    else
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.22/ciphervault-v1.0.22-x86_64-apple-darwin.tar.gz"
      sha256 "50c77cf1cbf65198785f59b63d4e23ba33166c95b38cb4c28959118673d82b6d"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.22/ciphervault-v1.0.22-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "4ac943e3fcce635b3e6563d632fc5451fb318ad8a442ea9b9c95e44d6594710c"
    else
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.22/ciphervault-v1.0.22-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "b9e709441ea9393aa0a13c83c81b7f24694ad0d19d35e5275cb61e998f26f384"
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
