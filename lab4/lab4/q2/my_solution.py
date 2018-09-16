
# I will solve this by finding which line has two or more blocks that looks same
with open("jdibsyenkxs5hd.txt") as file:
    data=file.read()
    data_string = (data)
    answer = ""

my_list = data_string.split("\n")
my_list = my_list[:-1]

for i in range(len(my_list)):  #iterating over the lines
    for j in range(10):        #iterating over the block
        for k in range(10):    #to check if jth block is similar to the kth block
               if (my_list[i][j*32:(j+1)*32] == my_list[i][k*32:(k+1)*32] and j != k) :
                    answer = i




print(answer)
#382dc447c96d2d5df4f60cd07fa94680 repeats 12 times in line 91st counting from 0. Thus
#it must be produced from ecb

                    

                    
