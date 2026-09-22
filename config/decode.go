/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package config

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

type configSectionDecoder func(conf *Config, section *config_parser.Section) error

type configSectionSpec struct {
	name     string
	required bool
	decode   configSectionDecoder
}

var configSectionSpecs = []configSectionSpec{
	{name: "global", required: true, decode: decodeGlobalSection},
	{name: "subscription", decode: decodeSubscriptionSection},
	{name: "node", decode: decodeNodeSection},
	{name: "group", decode: decodeGroupSection},
	{name: "rule_provider", decode: decodeRuleProviderSection},
	{name: "routing", required: true, decode: decodeRoutingSection},
	{name: "dns", decode: decodeDnsSection},
}

func lookupConfigSectionSpec(sectionName string) *configSectionSpec {
	for i := range configSectionSpecs {
		if configSectionSpecs[i].name == sectionName {
			return &configSectionSpecs[i]
		}
	}
	return nil
}

func decodeConfigSection(conf *Config, sectionName string, section *config_parser.Section) error {
	if conf == nil {
		return fmt.Errorf("nil config")
	}
	spec := lookupConfigSectionSpec(sectionName)
	if spec == nil {
		return fmt.Errorf("unknown section: %v", sectionName)
	}
	if section == nil {
		return fmt.Errorf("nil section: %v", sectionName)
	}
	return spec.decode(conf, section)
}

func decodeGlobalSection(conf *Config, section *config_parser.Section) error {
	if err := SectionParser(reflect.ValueOf(&conf.Global), section); err != nil {
		return err
	}
	if err := validateRuleProviderUpdateInterval(section); err != nil {
		return err
	}
	conf.Global.SoMarkFromDaeSet = sectionHasParam(section, "so_mark_from_dae")
	return nil
}

func validateRuleProviderUpdateInterval(section *config_parser.Section) error {
	for _, item := range section.Items {
		param, ok := item.Value.(*config_parser.Param)
		if !ok || param.Key != "rule_provider_update_interval" {
			continue
		}
		if _, err := parseRuleProviderUpdateInterval(param.Val); err != nil {
			return fmt.Errorf("parse rule_provider_update_interval: %w", err)
		}
	}
	return nil
}

func parseRuleProviderUpdateInterval(raw string) (time.Duration, error) {
	value := strings.TrimSpace(raw)
	if value == "0" {
		return 0, nil
	}
	if len(value) < 2 {
		return 0, fmt.Errorf("expected duration like 30s or 1d")
	}
	unit := value[len(value)-1]
	if unit != 's' && unit != 'd' {
		return 0, fmt.Errorf("unsupported unit %q, expected s or d", string(unit))
	}
	n, err := strconv.ParseInt(value[:len(value)-1], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid number %q: %w", value[:len(value)-1], err)
	}
	if n < 0 {
		return 0, fmt.Errorf("must be non-negative")
	}
	duration, err := common.ParseDurationWithDays(value)
	if err != nil {
		return 0, err
	}
	return duration, nil
}

func decodeSubscriptionSection(conf *Config, section *config_parser.Section) error {
	return SectionParser(reflect.ValueOf(&conf.Subscription), section)
}

func decodeNodeSection(conf *Config, section *config_parser.Section) error {
	return SectionParser(reflect.ValueOf(&conf.Node), section)
}

func decodeGroupSection(conf *Config, section *config_parser.Section) error {
	return SectionParser(reflect.ValueOf(&conf.Group), section)
}

func decodeRuleProviderSection(conf *Config, section *config_parser.Section) error {
	if err := SectionParser(reflect.ValueOf(&conf.RuleProvider), section); err != nil {
		return err
	}
	_, err := KeyableStringMap(conf.RuleProvider)
	return err
}

func decodeRoutingSection(conf *Config, section *config_parser.Section) error {
	return SectionParser(reflect.ValueOf(&conf.Routing), section)
}

func decodeDnsSection(conf *Config, section *config_parser.Section) error {
	return SectionParser(reflect.ValueOf(&conf.Dns), section)
}
