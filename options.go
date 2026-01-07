// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package envelope

import (
	"errors"
)

type options struct {
	length      *int64
	header      *Header
	aad         []byte
	omitKeyData bool
}

// GetOpts iterates the inbound options and returns a struct
func getOpts(opt ...Option) (*options, error) {
	opts := &options{}
	for _, o := range opt {
		if o == nil {
			continue
		}
		iface := o()
		switch to := iface.(type) {
		case OptionFunc:
			if err := to(opts); err != nil {
				return nil, err
			}
		default:
			return nil, errors.New("option passed into top-level wrapping options handler" +
				" that is not from this package; this is likely due to the wrapper being" +
				" invoked as a plugin but options being sent from a subpackage")
		}
	}
	return opts, nil
}

// Option - a type that wraps an interface for compile-time safety but can
// contain an option for this package or for wrappers implementing this
// interface.
type Option func() interface{}

// OptionFunc - a type for funcs that operate on the shared options struct. The
// options below explicitly wrap this so that we can switch on it when parsing
// opts for various wrappers.
type OptionFunc func(*options) error

// WithAad provides optional additional authenticated data
func WithAad(with []byte) Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.aad = with
			return nil
		})
	}
}

func WithHeader(with *Header) Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.header = with
			return nil
		})
	}
}

func WithOmitKeyData(with bool) Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.omitKeyData = with
			return nil
		})
	}
}

func WithLength(with *int64) Option {
	return func() interface{} {
		return OptionFunc(func(o *options) error {
			o.length = with
			return nil
		})
	}
}
