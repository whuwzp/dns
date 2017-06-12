import random
import xlrd
from xlwt import *

class nos:
    def __init__(self):
        self.id = 0
        self.kind = 0
        self.host = 0


if __name__ == '__main__':
    nos_list =[] #0~12
    #init
    for i in range(12):
        a = nos()
        a.id = i
        if i >= 0 and i <= 2:
            a.kind = 1
        elif i >= 3 and i <= 5:
            a.kind = 2
        elif i >= 6 and i <= 8:
            a.kind = 3
        else:
            a.kind = 4

        b = random.randint(1,4)
        a.host = b

        nos_list.append(a)

    cur_list = [nos_list[0],nos_list[1],nos_list[2],nos_list[3],nos_list[4]]
    cur_list_random = cur_list

    all_score = []
    all_score_random = []
    for loop in range(100):
        #find most damage
        same_num_list = []
        for kind in range(1,5):
            same_num = 0
            for c in cur_list:
                if c.kind == kind :
                    same_num += 1


            same_num_list.append(same_num)
        the_one_num = same_num_list.index(max(same_num_list))
        # print same_num_list, the_one_num

        for c in cur_list:
            if c.kind == the_one_num + 1:
                the_one = c
                break
        # print the_one,the_one.id

        #find the DG
        theta = 0.1
        gama = 0.3
        score_list = []
        for c in nos_list:
            score_list.append(0)
            if c not in cur_list:
                kind_score = gama
                host_score = gama

                for cur_c in cur_list:
                    if cur_c.kind == c.kind:
                        kind_score = theta
                        break
                for cur_c in cur_list:
                    if cur_c.host == c.host:
                        host_score = theta
                        break

                score_list[-1] = kind_score+host_score
        the_nxt_one_num = score_list.index(max(score_list))


        #random
        the_one_num_random = random.randint(0,4)
        the_nxt_one_num_random = random.randint(0,11)

        kind_score = gama
        host_score = gama
        for cur_c in cur_list_random:
            if cur_c.kind == nos_list[the_nxt_one_num_random].kind:
                kind_score = theta
                break
        for cur_c in cur_list:
            if cur_c.host == nos_list[the_nxt_one_num_random].host:
                host_score = theta
                break

        del cur_list_random[the_one_num_random]
        cur_list_random.append(nos_list[the_nxt_one_num_random])

        all_score_random.append(kind_score+host_score)

        # our way
        del cur_list[the_one_num]
        cur_list.append(nos_list[the_nxt_one_num])
        score = score_list[the_nxt_one_num]
        print score
        all_score.append(score)

    file = Workbook(encoding='utf-8')

    file_name = 'result.xls'

    table = file.add_sheet(file_name)

    for i in range(len(all_score)):
        table.write(i, 0, i)
        table.write(i, 1, all_score[i])
        table.write(i, 2, all_score_random[i])
    file.save(file_name)













