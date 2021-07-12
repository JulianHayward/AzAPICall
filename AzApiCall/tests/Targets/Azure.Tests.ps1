Describe -Name 'Test Azure Connection' -Fixture { 

    Context -Name "Validate Azure Management API Connection" -Fixture {
        BeforeAll {
            $testParams = @{
                Method         = 'Post'
                uri            = 'https://management.azure.com/subscriptions/**subscriptionId**/resourceGroups/**resourceGroupName**/providers/Microsoft.ApiManagement/service/**serviceName**/groups/**groupId**?api-version=2019-12-01'
            }

            Mock -CommandName AzApiCall -MockWith { 
                return $null
            }
        }

        
        It "Should return Values from GET" {
            $Global:DscHelper.DescribeHeader
        }

        It "Should return Values from POST" {
            $Global:DscHelper.DescribeHeader
        }

        It "Should return Value from Delete" {
            
        }
    }
}