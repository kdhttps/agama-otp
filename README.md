# Agama TOTP Project

Use this project to add user authentication with OTOP(Time-based One-time Passwords) 2-factor authentication.

## How it works at a glance

When then main flow of this project is launched (namely, `org.gluu.agama.totp.main`) it shows login page. User enters username and password. After user authn, OTP enrollmen page open for new user and if user is already enrolled then it will directly ask for OTP.

```mermaid
sequenceDiagram

title Agama TOTP Project Flow

participant browser as Browser
participant rp as RP
participant jans as Jans Authz Server

autonumber
browser->>rp: Request page
rp->>jans: Invoke /authorize endpoint
loop n times - (multistep authentication)
jans->>browser: Present Login screen
browser->>browser: Present Login credentials
end
jans->>jans: Authenticate user
opt if new user
jans->>browser: Present OTP enrollment page with QR-Code
browser->>browser: Scan QR-Code in OTP Auth App and enter OTP
jans->>jans: Validate OTP and save secrey key to user
end
opt if enrolled user
jans->>browser: Present OTP page to enter OTP
browser->>browser: enter OTP
jans->>jans: Validate OTP
end
jans->>jans: Create internal Jans session
jans->>rp: Redirect with Success response
rp->>rp: Validate response
rp->>browser: Page is accessed
```
