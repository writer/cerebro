package sync

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
)

func (e *SyncEngine) lambdaFunctionTable() TableSpec {
	return TableSpec{
		Name:    "aws_lambda_functions",
		Columns: []string{"arn", "account_id", "region", "function_name", "name", "runtime", "role", "handler", "code_size", "timeout", "memory_size", "environment", "description", "vpc_config", "last_modified"},
		Fetch:   e.fetchLambdaFunctions,
	}
}

func (e *SyncEngine) fetchLambdaFunctions(ctx context.Context, cfg aws.Config, region string) ([]map[string]interface{}, error) {
	client := lambda.NewFromConfig(cfg)
	accountID := e.getAccountIDFromConfig(ctx, cfg)

	var rows []map[string]interface{}
	paginator := lambda.NewListFunctionsPaginator(client, &lambda.ListFunctionsInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, fn := range page.Functions {
			var env interface{}
			if fn.Environment != nil {
				env = fn.Environment.Variables
			}

			rows = append(rows, map[string]interface{}{
				"_cq_id":        aws.ToString(fn.FunctionArn),
				"arn":           aws.ToString(fn.FunctionArn),
				"account_id":    accountID,
				"region":        region,
				"function_name": aws.ToString(fn.FunctionName),
				"name":          aws.ToString(fn.FunctionName),
				"runtime":       string(fn.Runtime),
				"role":          aws.ToString(fn.Role),
				"handler":       aws.ToString(fn.Handler),
				"code_size":     fn.CodeSize,
				"timeout":       fn.Timeout,
				"memory_size":   fn.MemorySize,
				"environment":   env,
				"description":   aws.ToString(fn.Description),
				"vpc_config":    fn.VpcConfig,
				"last_modified": aws.ToString(fn.LastModified),
			})
		}
	}
	return rows, nil
}
