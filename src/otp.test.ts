import { describe, it, expect } from "vitest"
import { Effect } from "effect"
import * as OTP from "./Otp.js"

describe("OTP Secret Generation", () => {
  it("should generate random bytes", async () => {
    const secret = await Effect.runPromise(OTP.generateSecret(20))
    
    expect(secret).toBeInstanceOf(Buffer)
    expect(secret.length).toBe(20)
  })

  it("should generate different secrets each time", async () => {
    const secret1 = await Effect.runPromise(OTP.generateSecret(20))
    const secret2 = await Effect.runPromise(OTP.generateSecret(20))
    
    expect(secret1.equals(secret2)).toBe(false)
  })

  it("should generate base32-encoded secret", async () => {
    const secret = await Effect.runPromise(OTP.generateBase32Secret(20))
    
    expect(typeof secret).toBe("string")
    expect(secret.length).toBeGreaterThan(0)
    // Base32 should only contain A-Z and 2-7
    expect(/^[A-Z2-7]+$/.test(secret)).toBe(true)
  })
})

describe("Base32 Encoding/Decoding", () => {
  it("should encode and decode correctly", async () => {
    const original = Buffer.from("Hello, World!")
    const encoded = OTP.encodeBase32(original)
    const decoded = await Effect.runPromise(OTP.decodeBase32(encoded))
    
    expect(decoded.toString()).toBe(original.toString())
  })

  it("should handle empty buffer", async () => {
    const original = Buffer.from("")
    const encoded = OTP.encodeBase32(original)
    const decoded = await Effect.runPromise(OTP.decodeBase32(encoded))
    
    expect(decoded.toString()).toBe("")
  })

  it("should decode lowercase base32", async () => {
    const uppercase = "JBSWY3DPEBLW64TMMQ======"
    const lowercase = uppercase.toLowerCase()
    
    const decodedUpper = await Effect.runPromise(OTP.decodeBase32(uppercase))
    const decodedLower = await Effect.runPromise(OTP.decodeBase32(lowercase))
    
    expect(decodedUpper.equals(decodedLower)).toBe(true)
  })

  it("should handle padding characters", async () => {
    const withPadding = "JBSWY3DPEBLW64TMMQ======"
    const withoutPadding = "JBSWY3DPEBLW64TMMQ"
    
    const decoded1 = await Effect.runPromise(OTP.decodeBase32(withPadding))
    const decoded2 = await Effect.runPromise(OTP.decodeBase32(withoutPadding))
    
    expect(decoded1.equals(decoded2)).toBe(true)
  })

  it("should fail on invalid base32 characters", async () => {
    const result = await Effect.runPromise(
      Effect.either(OTP.decodeBase32("INVALID@CHARS"))
    )
    
    expect(result._tag).toBe("Left")
  })
})

describe("HOTP (RFC 4226)", () => {
  // RFC 4226 Appendix D - Test Values
  // Secret: "12345678901234567890" (ASCII) = 0x3132333435363738393031323334353637383930
  const rfcSecret = Buffer.from("12345678901234567890", "ascii")
  
  // Expected HOTP values from RFC 4226
  const rfcTestVectors = [
    { counter: 0, otp: "755224" },
    { counter: 1, otp: "287082" },
    { counter: 2, otp: "359152" },
    { counter: 3, otp: "969429" },
    { counter: 4, otp: "338314" },
    { counter: 5, otp: "254676" },
    { counter: 6, otp: "287922" },
    { counter: 7, otp: "162583" },
    { counter: 8, otp: "399871" },
    { counter: 9, otp: "520489" },
  ]

  rfcTestVectors.forEach(({ counter, otp }) => {
    it(`should generate correct HOTP for counter ${counter}`, async () => {
      const result = await Effect.runPromise(
        OTP.generateHOTP(rfcSecret, counter, { digits: 6, algorithm: "sha1" })
      )
      
      expect(result).toBe(otp)
    })
  })

  it("should verify correct HOTP token", async () => {
    const token = "755224"
    const isValid = await Effect.runPromise(
      OTP.verifyHOTP(token, rfcSecret, 0, { digits: 6, algorithm: "sha1" })
    )
    
    expect(isValid).toBe(true)
  })

  it("should reject incorrect HOTP token", async () => {
    const token = "123456"
    const isValid = await Effect.runPromise(
      OTP.verifyHOTP(token, rfcSecret, 0, { digits: 6, algorithm: "sha1" })
    )
    
    expect(isValid).toBe(false)
  })

  it("should reject HOTP with wrong counter", async () => {
    const token = "755224" // Valid for counter 0
    const isValid = await Effect.runPromise(
      OTP.verifyHOTP(token, rfcSecret, 1, { digits: 6, algorithm: "sha1" })
    )
    
    expect(isValid).toBe(false)
  })

  it("should support different digit lengths", async () => {
    const result = await Effect.runPromise(
      OTP.generateHOTP(rfcSecret, 0, { digits: 8, algorithm: "sha1" })
    )
    
    expect(result.length).toBe(8)
  })

  it("should work with base32-encoded secret", async () => {
    const base32Secret = OTP.encodeBase32(rfcSecret)
    const result = await Effect.runPromise(
      OTP.generateHOTP(base32Secret, 0, { digits: 6, algorithm: "sha1" })
    )
    
    expect(result).toBe("755224")
  })
})

describe("TOTP (RFC 6238)", () => {
  // RFC 6238 Appendix B - Test Values
  // Secret: "12345678901234567890" (ASCII)
  const rfcSecret = Buffer.from("12345678901234567890", "ascii")
  const rfcSecret32 = Buffer.from("12345678901234567890123456789012", "ascii")

  // Note: We can't test exact time-based values without mocking Date.now()
  // But we can test the TOTP generation and verification logic
  
  it("should generate TOTP token", async () => {
    const base32Secret = OTP.encodeBase32(rfcSecret)
    const result = await Effect.runPromise(
      OTP.generateTOTP(base32Secret, { digits: 6, period: 30, algorithm: "sha1" })
    )
    
    expect(result).toBeDefined()
    expect(result.length).toBe(6)
    expect(/^\d+$/.test(result)).toBe(true)
  })

  it("should verify correct TOTP token", async () => {
    const base32Secret = OTP.encodeBase32(rfcSecret)
    
    // Generate and immediately verify
    const token = await Effect.runPromise(
      OTP.generateTOTP(base32Secret, { digits: 6, period: 30, algorithm: "sha1" })
    )
    
    const isValid = await Effect.runPromise(
      OTP.verifyTOTP(token, base32Secret, { digits: 6, period: 30, algorithm: "sha1" })
    )
    
    expect(isValid).toBe(true)
  })

  it("should reject incorrect TOTP token", async () => {
    const base32Secret = OTP.encodeBase32(rfcSecret)
    const isValid = await Effect.runPromise(
      OTP.verifyTOTP("000000", base32Secret, { digits: 6, period: 30, algorithm: "sha1" })
    )
    
    expect(isValid).toBe(false)
  })

  it("should work with default config", async () => {
    const base32Secret = OTP.encodeBase32(rfcSecret)
    const token = await Effect.runPromise(
      OTP.generateTOTP(base32Secret)
    )
    
    expect(token.length).toBe(6)
    
    const isValid = await Effect.runPromise(
      OTP.verifyTOTP(token, base32Secret)
    )
    
    expect(isValid).toBe(true)
  })

  it("should support different algorithms", async () => {
    const base32Secret = OTP.encodeBase32(rfcSecret32)
    
    const sha256Token = await Effect.runPromise(
      OTP.generateTOTP(base32Secret, { algorithm: "sha256" })
    )
    
    expect(sha256Token.length).toBe(6)
  })

  it("should support custom period", async () => {
    const base32Secret = OTP.encodeBase32(rfcSecret)
    
    const token = await Effect.runPromise(
      OTP.generateTOTP(base32Secret, { period: 60 })
    )
    
    const isValid = await Effect.runPromise(
      OTP.verifyTOTP(token, base32Secret, { period: 60 })
    )
    
    expect(isValid).toBe(true)
  })

  it("should verify tokens within window", async () => {
    const base32Secret = OTP.encodeBase32(rfcSecret)
    
    // Generate token with current time
    const token = await Effect.runPromise(
      OTP.generateTOTP(base32Secret, { digits: 6, period: 30, algorithm: "sha1" })
    )
    
    // Verify with a window of 1 (should accept previous and next time steps)
    const isValid = await Effect.runPromise(
      OTP.verifyTOTP(token, base32Secret, { digits: 6, period: 30, algorithm: "sha1", window: 1 })
    )
    
    expect(isValid).toBe(true)
  })
})

describe("OTP URI Generation", () => {
  it("should generate TOTP URI", () => {
    const uri = OTP.generateOTPURI({
      type: "totp",
      label: "user@example.com",
      issuer: "MyApp",
      secret: "JBSWY3DPEHPK3PXP",
    })
    
    expect(uri).toContain("otpauth://totp/")
    expect(uri).toContain("MyApp:user%40example.com")
    expect(uri).toContain("secret=JBSWY3DPEHPK3PXP")
    expect(uri).toContain("issuer=MyApp")
  })

  it("should generate HOTP URI with counter", () => {
    const uri = OTP.generateOTPURI({
      type: "hotp",
      label: "user@example.com",
      issuer: "MyApp",
      secret: "JBSWY3DPEHPK3PXP",
      counter: 0,
    })
    
    expect(uri).toContain("otpauth://hotp/")
    expect(uri).toContain("counter=0")
  })

  it("should include optional parameters", () => {
    const uri = OTP.generateOTPURI({
      type: "totp",
      label: "user@example.com",
      issuer: "MyApp",
      secret: "JBSWY3DPEHPK3PXP",
      period: 60,
      digits: 8,
      algorithm: "sha256",
    })
    
    expect(uri).toContain("period=60")
    expect(uri).toContain("digits=8")
    expect(uri).toContain("algorithm=SHA256")
  })

  it("should encode special characters in label and issuer", () => {
    const uri = OTP.generateOTPURI({
      type: "totp",
      label: "user+test@example.com",
      issuer: "My App & Co.",
      secret: "JBSWY3DPEHPK3PXP",
    })
    
    expect(uri).toContain("My%20App%20%26%20Co.")
    expect(uri).toContain("user%2Btest%40example.com")
  })

  it("should not include default values", () => {
    const uri = OTP.generateOTPURI({
      type: "totp",
      label: "user@example.com",
      issuer: "MyApp",
      secret: "JBSWY3DPEHPK3PXP",
      period: 30, // default
      digits: 6, // default
      algorithm: "sha1", // default
    })
    
    expect(uri).not.toContain("period=")
    expect(uri).not.toContain("digits=")
    expect(uri).not.toContain("algorithm=")
  })
})

describe("Integration Tests", () => {
  it("should work end-to-end for TOTP enrollment", async () => {
    // Step 1: Generate a secret
    const secret = await Effect.runPromise(OTP.generateBase32Secret(20))
    
    // Step 2: Generate URI for QR code
    const uri = OTP.generateOTPURI({
      type: "totp",
      label: "test@example.com",
      issuer: "TestApp",
      secret,
    })
    
    expect(uri).toContain("otpauth://totp/")
    
    // Step 3: Generate TOTP
    const token = await Effect.runPromise(OTP.generateTOTP(secret))
    
    // Step 4: Verify TOTP
    const isValid = await Effect.runPromise(OTP.verifyTOTP(token, secret))
    
    expect(isValid).toBe(true)
  })

  it("should work end-to-end for HOTP enrollment", async () => {
    // Step 1: Generate a secret
    const secret = await Effect.runPromise(OTP.generateBase32Secret(20))
    
    // Step 2: Generate URI for QR code with initial counter
    const uri = OTP.generateOTPURI({
      type: "hotp",
      label: "test@example.com",
      issuer: "TestApp",
      secret,
      counter: 0,
    })
    
    expect(uri).toContain("otpauth://hotp/")
    expect(uri).toContain("counter=0")
    
    // Step 3: Generate HOTP for counter 0
    const token = await Effect.runPromise(OTP.generateHOTP(secret, 0))
    
    // Step 4: Verify HOTP
    const isValid = await Effect.runPromise(OTP.verifyHOTP(token, secret, 0))
    
    expect(isValid).toBe(true)
  })
})

describe("Input Validation and Edge Cases", () => {
  const validSecret = OTP.encodeBase32(Buffer.from("12345678901234567890", "ascii"))

  describe("generateSecret validation", () => {
    it("should reject length less than 16 bytes", async () => {
      const result = await Effect.runPromise(
        Effect.either(OTP.generateSecret(15))
      )
      
      expect(result._tag).toBe("Left")
      if (result._tag === "Left") {
        expect(result.left._tag).toBe("HashingError")
        expect(result.left.message).toContain("at least 16 bytes")
      }
    })

    it("should reject negative length", async () => {
      const result = await Effect.runPromise(
        Effect.either(OTP.generateSecret(-1))
      )
      
      expect(result._tag).toBe("Left")
      if (result._tag === "Left") {
        expect(result.left._tag).toBe("HashingError")
      }
    })

    it("should reject non-integer length", async () => {
      const result = await Effect.runPromise(
        Effect.either(OTP.generateSecret(20.5))
      )
      
      expect(result._tag).toBe("Left")
      if (result._tag === "Left") {
        expect(result.left._tag).toBe("HashingError")
      }
    })
  })

  describe("generateHOTP validation", () => {
    it("should reject negative counter", async () => {
      const result = await Effect.runPromise(
        Effect.either(OTP.generateHOTP(validSecret, -1))
      )
      
      expect(result._tag).toBe("Left")
      if (result._tag === "Left") {
        expect(result.left._tag).toBe("HashingError")
        expect(result.left.message).toContain("non-negative")
      }
    })

    it("should reject non-integer counter", async () => {
      const result = await Effect.runPromise(
        Effect.either(OTP.generateHOTP(validSecret, 1.5))
      )
      
      expect(result._tag).toBe("Left")
      if (result._tag === "Left") {
        expect(result.left._tag).toBe("HashingError")
      }
    })

    it("should reject digits less than 6", async () => {
      const result = await Effect.runPromise(
        Effect.either(OTP.generateHOTP(validSecret, 0, { digits: 5 }))
      )
      
      expect(result._tag).toBe("Left")
      if (result._tag === "Left") {
        expect(result.left._tag).toBe("HashingError")
        expect(result.left.message).toContain("between 6 and 8")
      }
    })

    it("should reject digits greater than 8", async () => {
      const result = await Effect.runPromise(
        Effect.either(OTP.generateHOTP(validSecret, 0, { digits: 9 }))
      )
      
      expect(result._tag).toBe("Left")
      if (result._tag === "Left") {
        expect(result.left._tag).toBe("HashingError")
        expect(result.left.message).toContain("between 6 and 8")
      }
    })

    it("should reject empty string secret", async () => {
      const result = await Effect.runPromise(
        Effect.either(OTP.generateHOTP("", 0))
      )
      
      expect(result._tag).toBe("Left")
      if (result._tag === "Left") {
        expect(result.left._tag).toBe("HashingError")
        expect(result.left.message).toContain("non-empty")
      }
    })

    it("should reject empty buffer secret", async () => {
      const result = await Effect.runPromise(
        Effect.either(OTP.generateHOTP(Buffer.from([]), 0))
      )
      
      expect(result._tag).toBe("Left")
      if (result._tag === "Left") {
        expect(result.left._tag).toBe("HashingError")
        expect(result.left.message).toContain("cannot be empty")
      }
    })
  })

  describe("verifyHOTP validation", () => {
    it("should reject empty token", async () => {
      const result = await Effect.runPromise(
        OTP.verifyHOTP("", validSecret, 0)
      )
      
      expect(result).toBe(false)
    })

    it("should reject non-numeric token", async () => {
      const result = await Effect.runPromise(
        OTP.verifyHOTP("12a456", validSecret, 0)
      )
      
      expect(result).toBe(false)
    })

    it("should reject token with special characters", async () => {
      const result = await Effect.runPromise(
        OTP.verifyHOTP("123-456", validSecret, 0)
      )
      
      expect(result).toBe(false)
    })
  })

  describe("verifyTOTP validation", () => {
    it("should handle zero period by using default", async () => {
      const token = await Effect.runPromise(
        OTP.generateTOTP(validSecret)
      )
      
      // Verify with zero period should fall back to default (30)
      const result = await Effect.runPromise(
        OTP.verifyTOTP(token, validSecret, { period: 0 })
      )
      
      expect(result).toBe(true)
    })

    it("should handle negative period by using default", async () => {
      const token = await Effect.runPromise(
        OTP.generateTOTP(validSecret)
      )
      
      // Verify with negative period should fall back to default (30)
      const result = await Effect.runPromise(
        OTP.verifyTOTP(token, validSecret, { period: -10 })
      )
      
      expect(result).toBe(true)
    })

    it("should handle negative window by using default", async () => {
      const token = await Effect.runPromise(
        OTP.generateTOTP(validSecret)
      )
      
      // Verify with negative window should fall back to default (1)
      const result = await Effect.runPromise(
        OTP.verifyTOTP(token, validSecret, { window: -5 })
      )
      
      expect(result).toBe(true)
    })

    it("should floor non-integer period", async () => {
      const token = await Effect.runPromise(
        OTP.generateTOTP(validSecret, { period: 30 })
      )
      
      // Should floor 30.9 to 30 and work correctly
      const result = await Effect.runPromise(
        OTP.verifyTOTP(token, validSecret, { period: 30.9 })
      )
      
      expect(result).toBe(true)
    })
  })

  describe("generateOTPURI validation", () => {
    it("should reject empty secret", () => {
      expect(() => {
        OTP.generateOTPURI({
          type: "totp",
          label: "test@example.com",
          issuer: "Test",
          secret: "",
        })
      }).toThrow("cannot be empty")
    })

    it("should reject invalid base32 characters", () => {
      expect(() => {
        OTP.generateOTPURI({
          type: "totp",
          label: "test@example.com",
          issuer: "Test",
          secret: "INVALID@CHARS",
        })
      }).toThrow("Invalid Base32")
    })

    it("should reject non-string secret", () => {
      expect(() => {
        OTP.generateOTPURI({
          type: "totp",
          label: "test@example.com",
          issuer: "Test",
          secret: 123 as any,
        })
      }).toThrow("must be a string")
    })

    it("should require counter for HOTP", () => {
      expect(() => {
        OTP.generateOTPURI({
          type: "hotp",
          label: "test@example.com",
          issuer: "Test",
          secret: validSecret,
        })
      }).toThrow("Counter parameter is required")
    })

    it("should accept valid base32 with padding", () => {
      const uri = OTP.generateOTPURI({
        type: "totp",
        label: "test@example.com",
        issuer: "Test",
        secret: "JBSWY3DPEBLW64TMMQ======",
      })
      
      expect(uri).toContain("secret=JBSWY3DPEBLW64TMMQ")
    })

    it("should normalize secret to uppercase", () => {
      const uri = OTP.generateOTPURI({
        type: "totp",
        label: "test@example.com",
        issuer: "Test",
        secret: "jbswy3dpehpk3pxp",
      })
      
      expect(uri).toContain("secret=JBSWY3DPEHPK3PXP")
    })
  })
})
