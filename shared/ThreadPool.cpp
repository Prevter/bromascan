#include "ThreadPool.hpp"

utils::ThreadPool::ThreadPool(size_t threadCount) {
    m_workers.reserve(threadCount);
    for (size_t i = 0; i < threadCount; ++i) {
        m_workers.emplace_back(&ThreadPool::workerThread, this);
    }
}

utils::ThreadPool::~ThreadPool() {
    {
        std::unique_lock lock(m_queueMutex);
        m_stop = true;
    }
    m_condition.notify_all();
    for (auto& worker : m_workers) {
        if (worker.joinable()) {
            worker.join();
        }
    }
}

void utils::ThreadPool::enqueue(std::move_only_function<void()> task) {
    {
        std::unique_lock lock(m_queueMutex);
        m_tasks.emplace_back(std::move(task));
    }
    m_condition.notify_one();
}

void utils::ThreadPool::waitAll() {
    while (true) {
        {
            std::unique_lock lock(m_queueMutex);
            if (m_tasks.empty() && m_activeTasks.load() == 0) {
                break;
            }
        }
        std::this_thread::yield();
    }
}

bool utils::ThreadPool::isRunning() const {
    std::unique_lock lock(m_queueMutex);
    return !m_tasks.empty() || m_activeTasks.load() > 0;
}

void utils::ThreadPool::workerThread() {
    while (true) {
        std::move_only_function<void()> task;
        {
            std::unique_lock lock(m_queueMutex);
            m_condition.wait(lock, [this] { return m_stop.load() || !m_tasks.empty(); });
            if (m_stop.load() && m_tasks.empty()) {
                return;
            }
            task = std::move(m_tasks.back());
            m_tasks.pop_back();
            ++m_activeTasks;
        }
        task();
        --m_activeTasks;
    }
}
