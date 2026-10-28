# Reusable farmer dashboard

The farmer portal is company-neutral. It reads only the signed-in farmer's own collection records and does not assume a particular milk price, payout policy, SACCO, loan product, or banking provider.

## Included

- Farmer sign-in by a one-time six-digit code sent to the mobile number already held by the dairy. TextBee is preferred when `TEXTBEE_API_KEY` is configured; Africa's Talking is the fallback provider.
- Farmer monthly kilograms, recorded lifetime kilograms, a recent monthly trend, and up to 30 recent deliveries.
- An office form to update a farmer's sign-in phone. Staff must verify the farmer's identity and ownership of the number before changing it.
- A clear disconnected state for prices, milk payouts, savings, and loans. No finance values are guessed or derived from kilograms.

## API

- `POST /farmers/otp/request` with `{ "farmerNumber": "..." }`
- `POST /farmers/otp/verify` with `{ "farmerNumber": "...", "code": "123456" }`
- `GET /farmers/me` with the returned bearer token
- `PUT /admin/farmers/:farmerNumber/phone` with `{ "phone": "0712345678" }` and an office admin token

The OTP endpoints use generic responses to reduce account discovery. Codes expire after five minutes, are limited to five verification attempts, and phone-number requests are limited to five per hour with a one-minute resend delay. Farmer sessions expire after one hour and are checked against active status on each request. The portal does not save farmer tokens to persistent browser or device storage.

Farmer OTP uses the same SMS provider selection and credentials as the existing milk-collection receipt SMS. If the hosted backend is already sending those receipts successfully, no second SMS key or provider setup is needed; deploy the OTP-enabled backend to that same service so the new routes are available there.

## Before enabling for a dairy

- Set `DAIRY_COMPANY_NAME`, exact allowed CORS origins, HTTPS API hosting, production database TLS, and a production token secret.
- Configure an approved SMS provider and its production credentials. A sandbox provider cannot deliver live one-time codes to farmers.
- For TextBee, set `TEXTBEE_API_KEY` in the backend host's private environment. Optionally set `TEXTBEE_DEVICE_ID`; otherwise TextBee chooses its default/most recently active linked phone. The linked Android phone must be online with an active SIM. Keep the key off the APK and out of source control.
- Check farmer account numbers for uniqueness, make sure each active farmer has a verified current mobile number, and train office staff on identity checks before updating phone numbers.
- The OTP and sign-in throttle state currently lives in API process memory. Run one backend instance for this feature, or move OTP and rate-limit state into a shared store before using multiple replicas. A restart invalidates outstanding codes.
- Deploy the API changes before distributing an APK that exposes farmer sign-in. The current hosted service is documented separately as a test database; do not point farmer users at it for live records.

## Finance and SACCO integrations

The farmer dashboard intentionally has no direct access to a SACCO database. Add a financial panel only after the dairy/SACCO owners authorize the connection and provide an API or an approved export format, member matching rules, balance/statement definitions, and support ownership. Keep finance identity and authorization scoped independently from dairy login. Use verified ledger entries for amounts, deductions, net pay, savings, and loan balances; do not estimate these from milk weight.
