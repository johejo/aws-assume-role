// SPDX-License-Identifier: MIT
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

var (
	roleArn         string
	roleSessionName string
	duration        time.Duration
	externalID      string
	serialNumber    string
	tokenCode       string
	sourceIdentity  string
)

func init() {
	flag.StringVar(&roleArn, "role-arn", "", "role ARN (required)")
	flag.StringVar(&roleSessionName, "role-session-name", "", "role session name (default unix nano timestamp)")
	flag.DurationVar(&duration, "duration", 900*time.Second, "role session duration")
	flag.StringVar(&externalID, "external-id", "", "external ID")
	flag.StringVar(&serialNumber, "serial-number", "", "MFA serial number")
	flag.StringVar(&tokenCode, "token-code", "", "MFA token code provided by MFA device")
	flag.StringVar(&sourceIdentity, "source-identity", "", "source identity")
}

func main() {
	flag.Usage = func() {
		fmt.Fprintf(
			flag.CommandLine.Output(),
			"Usage: %s\n\n"+
				"  aws-assume-role -role-arn [ROLE ARN] -- [COMMANDS...]\n\n",
			os.Args[0],
		)
		flag.PrintDefaults()
	}
	flag.Parse()

	if roleArn == "" {
		log.Fatal("role-arn is required")
	}
	if roleSessionName == "" {
		roleSessionName = strconv.FormatInt(time.Now().UnixNano(), 10)
	}

	ctx := context.Background()

	ctx, cancel := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		log.Fatal(err)
	}

	stsClient := sts.NewFromConfig(cfg)

	role, err := stsClient.AssumeRole(ctx, &sts.AssumeRoleInput{
		RoleArn:         ptr(roleArn),
		RoleSessionName: ptr(roleSessionName),
		DurationSeconds: ptr(int32(duration.Seconds())),
		ExternalId:      ptr(externalID),
		SerialNumber:    ptr(serialNumber),
		SourceIdentity:  ptr(sourceIdentity),
		TokenCode:       ptr(tokenCode),
	})
	if err != nil {
		log.Fatal(err)
	}

	env := []string{
		"AWS_ACCESS_KEY_ID=" + *role.Credentials.AccessKeyId,
		"AWS_SECRET_ACCESS_KEY=" + *role.Credentials.SecretAccessKey,
		"AWS_SESSION_TOKEN=" + *role.Credentials.SessionToken,
	}
	for _, e := range os.Environ() {
		k, _, found := strings.Cut(e, "=")
		if !found {
			log.Fatal("invalid environ")
		}
		switch k {
		case
			"AWS_ROLE_ARN",
			"AWS_ACCESS_KEY_ID",
			"AWS_SECRET_ACCESS_KEY",
			"AWS_SESSION_TOKEN",
			"AWS_WEB_IDENTITY_TOKEN_FILE":
			continue
		}
		env = append(env, e)
	}

	args := flag.Args()
	var cmd *exec.Cmd
	if len(args) == 1 {
		cmd = exec.CommandContext(ctx, args[0])
	} else if len(args) > 1 {
		cmd = exec.CommandContext(ctx, args[0], args[1:]...)
	} else {
		log.Println("no commands")
		os.Exit(0)
	}
	cmd.Env = env
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	if err := cmd.Run(); err != nil {
		log.Fatal(err)
	}
}

func ptr[T any](v T) *T {
	if reflect.ValueOf(v).IsZero() {
		return nil
	}
	return &v
}
