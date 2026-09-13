/*
* Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
* Description:多线程测试框架(GTEST-MULTITHREAD)库，源码移植自CDK
* Author:
* Create:2023/2/24
*/

#include "gtest/hwext/gtest-multithread.h"
#include <iostream>
#include <pthread.h>
#include <utility>
#include <semaphore.h>
#include <fcntl.h>
#include <semaphore.h>
#include <iostream>
#include <algorithm>

namespace testing{
    namespace mt {
        static inline void doThreadTestTask(ThreadTaskEntry *task)
        {
            for (const auto &f : task->funcList){
                f.m_func();
            }
        }

        void MultiThreadTest::run()
        {
            int i = 0;
            for (const auto &_ : randomTasks) {
                for (const auto &val : _.second) {
                    auto pid = rand() % 100 + i;
                    appendTaskToList(pid, val.m_func, val.m_testsuite, val.m_testcase);
                }
                i++;
            }
            doTest();
        }

        void MultiThreadTest::doTest()
        {
            threadTestEntryList.clear();
            for (const auto &task : threadTasks){
                threadTestEntryList.push_back(ThreadTaskEntry(task));
            }
            for (auto &test : threadTestEntryList){
                test.thread = new std::thread(doThreadTestTask, &test);
            }
            auto check = [&](ThreadTaskEntry &t) -> void {
                if (t.thread){
                    t.thread->join();
                    delete t.thread;
                    t.thread = nullptr;
                }
            };
            std::for_each(threadTestEntryList.begin(), threadTestEntryList.end(), check);
        }

        unsigned MultiThreadTest::runTask(unsigned thread_num, PF func, std::string testsuite, std::string testcase)
        {
            MultiThreadFailCaseListener *listener = new MultiThreadFailCaseListener(this);
            testing::UnitTest::GetInstance()->listeners().Append(listener);
            if (thread_num == 0){
                func();
            }
            unsigned i = 0;
            for(; i < thread_num; i++){
                appendTaskToList(i, func, testsuite, testcase);
            }
            i = 0;
            for (const auto &_ : randomTasks){
                for (const auto &val : _.second){
                    auto pid = rand() % 100 + i;
                    appendTaskToList(pid, val.m_func, val.m_testsuite, val.m_testcase);
                }
                i++;
            }
            doTest();
            testing::UnitTest::GetInstance()->listeners().Release(listener);
            return 0;
        }

        void MultiThreadTest::appendTaskToList(unsigned thread_id, PF func, std::string testsuite, std::string testcase)
        {
            TestTask task(testsuite, testcase, func);
            if (thread_id == RANDOM_THREAD_ID){
                randomTasks[testsuite].emplace_back(task);
                return;
            }
            while (thread_id >= threadTasks.size()){
                threadTasks.push_back(std::vector<TestTask>());
            }
            threadTasks[thread_id].push_back(task);
        }
    }
}