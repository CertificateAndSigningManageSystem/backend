package route

import "backend/filter"

func InitialRouter() {
	_ = filter.AuthenticateFilter
	_ = filter.TransactionFilter
}
