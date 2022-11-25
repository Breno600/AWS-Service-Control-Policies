import boto3
import json
import re

client = boto3.client('sqs', region_name='us-east-2')
#Pega AccountId Atual
accountId = boto3.client('sts').get_caller_identity().get('Account')

def lambda_handler(event, context, prefix=None):
    
    list = client.list_queues();
    count = 0;
    #Percorre todas os sqs disponivel
    for queue in list['QueueUrls']:
        count = count + 1
        print(count)
        
        print('Nome da fila: ', queue);
        
        policy = client.get_queue_attributes( QueueUrl=queue, AttributeNames=['Policy']);
        
        #Percorre todos os Statement 
        if "Attributes" in policy:
            
            j = json.loads(policy.get("Attributes").get("Policy"))
            print('Json Policy: ', j);
            
            for statement in j["Statement"]:
                
                #Valida se a ação é de permitir
                if statement["Effect"] == "Allow":
                    
                    #Valida de o Principal da policy é um *
                    if statement["Principal"] == "*":
                        if "Sid" in statement:
                            policyId = statement["Sid"]
                            client.remove_permission(QueueUrl=queue, Label=policyId)
                            client.add_permission(QueueUrl=queue, Label=policyId+"-2", AWSAccountIds=[accountId], Actions=["SendMessage","DeleteMessage","ChangeMessageVisibility" ])
                        else:
                            print("Essa Fila não tem Sid: " + queue)
                            
                    if "Service" in statement["Principal"]:
    
                        #Valido sem tem um *
                        if statement["Principal"]["Service"] == "*":
                            if "Sid" in statement:
                                policyId = statement["Sid"]
                                client.remove_permission(QueueUrl=queue, Label=policyId)
                                client.add_permission(QueueUrl=queue, Label=policyId+"-2", AWSAccountIds=[accountId], Actions=["SendMessage","DeleteMessage","ChangeMessageVisibility" ])
                            else:
                                print("Essa Fila não tem Sid: " + queue)
                                #policyId = len(statement)
                                #client.remove_permission(QueueUrl=queue, Label=policyId)
                                #client.add_permission(QueueUrl=queue, Label=policyId+"-2", AWSAccountIds=[accountId], Actions=["SendMessage"])
                    
                    #Valido se o Principal AWS é uma lista ou não
                    if "AWS" in statement["Principal"]:
                        #print("CAIU AQUI "+statement["Principal"]["AWS"])
                        
                        if type(statement["Principal"]["AWS"]) == str:
                            #print("CAIU AQUI "+statement["Principal"]["AWS"])
                            
                            #Valido sem tem um *
                            if statement["Principal"]["AWS"] == "*":
                                #print("CAIU AQUI ", statement)
                                
                                if "Sid" in statement:
                                    policyId = statement["Sid"]
                                    client.remove_permission(QueueUrl=queue, Label=policyId)
                                    client.add_permission(QueueUrl=queue, Label=policyId+"-2", AWSAccountIds=[accountId], Actions=["SendMessage","DeleteMessage","ChangeMessageVisibility" ])
                                else:
                                    print("Essa Fila não tem Sid: " + queue)
                                    client.remove_permission(QueueUrl=queue, Label="0")
                                    client.add_permission(QueueUrl=queue, Label="__owner_statement", AWSAccountIds=[accountId], Actions=["SendMessage","DeleteMessage","ChangeMessageVisibility"])
                                    print("Adicionado Policy para as que não tem SID")
                                
                        #Percorre a list em Principal AWS e faz validação se tem um *
                        else:
                            for methodDelete in statement["Principal"]["AWS"]:
                                
                                if methodDelete == "*":
                                    if "Sid" in statement:
                                        
                                        policyId = statement["Sid"]
                                        client.remove_permission(QueueUrl=queue, Label=policyId)
                                        client.add_permission(QueueUrl=queue, Label=policyId+"-2", AWSAccountIds=[methodDelete,accountId], Actions=["SendMessage","DeleteMessage","ChangeMessageVisibility" ])
                                    else:
                                        print("Essa Fila não tem Sid: " + queue)
        else: 
            print("Essa Fila não tem Policy: " + queue)
            client.add_permission(QueueUrl=queue, Label="__owner_statement", AWSAccountIds=[accountId], Actions=["SendMessage","DeleteMessage","ChangeMessageVisibility" ])
            print("Policy Adicionada")

    return "Esta Tudo Certo...";
