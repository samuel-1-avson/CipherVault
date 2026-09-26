class Ciphervault < Formula
  desc "Decentralized, zero-knowledge encrypted version control for confidential files"
  homepage "https://github.com/samuel-1-avson/CipherVault"
  version "1.0.16"
  license "MIT OR Apache-2.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.16/ciphervault-v1.0.16-aarch64-apple-darwin.tar.gz"
      sha256 "1051e2c470b0bd7b86fb4cb6f48dd282480471e87bff0dcc519c71246928fbac"
    else
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.16/ciphervault-v1.0.16-x86_64-apple-darwin.tar.gz"
      sha256 "73b97e20d80b9c22f8b720d1517d88f30f782d1c99236170152ee4318809aaae"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.16/ciphervault-v1.0.16-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "509624552ed3f00eeee28018fe5f7a5be0c99338a10eb466c6bc6880d69f35f2"
    else
      url "https://github.com/samuel-1-avson/CipherVault/releases/download/v1.0.16/ciphervault-v1.0.16-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "3cccb5915913631fb775aa635920a411b93b8eab865e3358aefa747f8caedd64"
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
