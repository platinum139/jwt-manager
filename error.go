package jwt_manager

type InvalidTokenError struct{}

func (e InvalidTokenError) Error() string {
    return "invalid token"
}

type ExpiredTokenError struct{}

func (e ExpiredTokenError) Error() string {
    return "expired token"
}

type InvalidSignatureError struct{}

func (e InvalidSignatureError) Error() string {
    return "invalid signature"
}
