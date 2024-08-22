#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <cstdint>
#include <pthread.h>
#include <filesystem>
#include "LuceneHeaders.h"
#include "Document.h"
#include "Field.h"
#include "Term.h"
#include "TermQuery.h"
#include "TopFieldDocs.h"
#include "IndexWriter.h"
#include "IndexSearcher.h"
#include "KeywordAnalyzer.h"
#include "Query.h"

extern "C" {
#include "ldb/tag.h"
#include "ldb/logger.h"
#include "hrperf_api.h"
}

#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)
#define barrier()       asm volatile("" ::: "memory")

#define CYCLES_PER_US 2396

using namespace Lucene;

constexpr uint64_t NORM = 100;
constexpr int searchN = 100;
constexpr uint16_t kLucenePort = 8001;

std::vector<String> terms;
std::vector<uint64_t> frequencies;
uint64_t weight_sum;
RAMDirectoryPtr dir;

struct payload {
  uint64_t term_index;
  uint64_t index;
  uint64_t hash;
};

static inline __attribute__((always_inline)) uint64_t rdtsc(void) {
  uint32_t a, d;
  asm volatile("rdtsc" : "=a" (a), "=d" (d));
  return ((uint64_t)a) | (((uint64_t)d) << 32);
}

static uint64_t mc_swap64(uint64_t in) {
    /* Little endian, flip the bytes around until someone makes a faster/better
    * way to do this. */
    int64_t rv = 0;
    int i = 0;
     for(i = 0; i<8; i++) {
        rv = (rv << 8) | (in & 0xff);
        in >>= 8;
     }
    return rv;
}

uint64_t ntohll(uint64_t val) {
   return mc_swap64(val);
}

uint64_t htonll(uint64_t val) {
   return mc_swap64(val);
}

int TcpListen(uint16_t port, int backlog) {
  int fd;
  int opt = 1;
  struct sockaddr_in addr;

  if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    fprintf(stderr, "Failed to create socket\n");
    return -1;
  }

  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
    fprintf(stderr, "Failed to set socket options\n");
    return -1;
  }

  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port = htons(port);

  if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
    fprintf(stderr, "Failed to bind\n");
    return -1;
  }

  if (listen(fd, backlog) < 0) {
    fprintf(stderr, "Failed to listen\n");
    return -1;
  }

  return fd;
}

int TcpAccept(int fd, uint16_t port) {
  int s;
  struct sockaddr_in addr;
  int addrlen = sizeof(addr);

  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port = htons(port);

  if ((s = accept(fd, (struct sockaddr *)&addr, (socklen_t*)&addrlen)) < 0) {
    fprintf(stderr, "Failed to accept\n");
    return -1;
  }

  return s;
}

int TcpDial(unsigned long ip, uint16_t port) {
  int fd;
  struct sockaddr_in addr;

  if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    fprintf(stderr, "Failed to create a socket\n");
    return -1;
  }
  bzero(&addr, sizeof(addr));

  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = ip;
  addr.sin_port = htons(port);

  if (connect(fd, (struct sockaddr *)&addr, sizeof(addr))) {
    fprintf(stderr, "Failed to connect: port = %u\n", port);
    return -1;
  }

  return fd;
}

ssize_t TcpReadFull(int fd, void *buf, size_t len) {
  char *pos = reinterpret_cast<char *>(buf);
  size_t n = 0;
  while (n < len) {
    ssize_t ret = read(fd, pos + n, len - n);
    if (ret < 0) return ret;
    n += ret;
  }
  assert(n == len);
  return n;
}

ssize_t TcpWriteFull(int fd, const void *buf, size_t len) {
  const char *pos = reinterpret_cast<const char *>(buf);
  size_t n = 0;
  while (n < len) {
    ssize_t ret = send(fd, buf, len, 0);
    if (ret < 0) return ret;
    assert(ret > 0);
    n += ret;
  }
  assert(n == len);
  return n;
}

String ChooseTerm() {
  uint64_t rand_ = (uint64_t)rand() % weight_sum;
  int i;

  for(i = 0; i < frequencies.size(); ++i) {
    if (rand_ < frequencies[i]) {
      break;
    } else {
      rand_ -= frequencies[i];
    }
  }

  return terms[i];
}

String ChooseTerm(uint64_t hash) {
  uint64_t rand_ = hash % weight_sum;
  int i;

  for(i = 0; i < frequencies.size(); ++i) {
    if (rand_ < frequencies[i]) {
      break;
    } else {
      rand_ -= frequencies[i];
    }
  }

  return terms[i];
}

void ReadFreqTerms() {
    std::cout << "Reading csv ...\t" << std::flush;
    std::ifstream fin("frequent_terms.csv");

    std::string line, word;
    String wword;
    uint64_t freq;

    weight_sum = 0;

    while(std::getline(fin, line)) {
        std::stringstream ss(line);

        getline(ss, word, ',');
        wword = String(word.length(), L' ');
        std::copy(word.begin(), word.end(), wword.begin());
        terms.push_back(wword);

        getline(ss, word, ',');

        try {
            freq = std::stoi(word) / NORM;
            frequencies.push_back(freq);
            weight_sum += freq;
        } catch (const std::invalid_argument& e) {
            std::cerr << "Invalid argument: " << word << " in line: " << line << std::endl;
            // Optionally, handle the error, e.g., skip this entry or set freq to a default value
        } catch (const std::out_of_range& e) {
            std::cerr << "Out of range: " << word << " in line: " << line << std::endl;
            // Handle out of range error
        }
    }

    fin.close();
    std::cout << "Done" << std::endl;
}

std::string sanitizeString(const std::string& input) {
    std::string result;
    for (char c : input) {
        // Check if the character should be kept
        if ((c >= 'a' && c <= 'z') || // lowercase letters
            (c >= 'A' && c <= 'Z') || // uppercase letters
            (c == ' ') ||             // space
            (c == ',') ||             // comma
            (c == '.')) {             // period
            result += c;
        }
    }
    return result;
}

DocumentPtr createDocument(const String& contents) {
    if (contents.empty()) {
        std::cerr << "Empty contents received for document creation." << std::endl;
        return nullptr;  // Return nullptr if contents are empty to prevent creating empty documents.
    }
    
    DocumentPtr document = newLucene<Document>();
    if (!document) {
        std::cerr << "Failed to create a new document instance." << std::endl;
        return nullptr;
    }
    
    try {
        document->add(newLucene<Field>(L"contents", contents, Field::STORE_YES, Field::INDEX_ANALYZED));
    } catch (const LuceneException& e) {
        std::cerr << "Lucene exception in document field addition" << std::endl;
        return nullptr;
    } catch (const std::exception& e) {
        std::cerr << "Standard exception in document field addition: " << e.what() << std::endl;
        return nullptr;
    }

    return document;
}

void PopulateIndex() {
    std::cout << "Populating indices ...\t" << std::flush;
    uint64_t start = rdtsc();
    int num_docs = 0;

    dir = newLucene<RAMDirectory>();
    if (!dir) {
        std::cerr << "Failed to create RAMDirectory instance." << std::endl;
        return;
    }

    IndexWriterPtr indexWriter = newLucene<IndexWriter>(dir, newLucene<StandardAnalyzer>(LuceneVersion::LUCENE_CURRENT), true, IndexWriter::MaxFieldLengthLIMITED);
    if (!indexWriter) {
        std::cerr << "Failed to create IndexWriter instance." << std::endl;
        return;
    }

    std::ifstream csvFile("test.csv");
    if (!csvFile.is_open()) {
        std::cerr << "Unable to open file" << std::endl;
        return;
    }

    std::string line;
    int iteration = 0; // Counter for iterations
    while (getline(csvFile, line)) {
        iteration++;
        if (iteration % 1000 == 0) {
            std::cerr << "Processing line #" << iteration << std::endl;
        }

        std::stringstream ss(line);
        std::string polarity, title, review;
        getline(ss, polarity, ',');
        getline(ss, title, ',');
        getline(ss, review, ',');
        review = sanitizeString(review);

        if (review.empty()) {
            // std::cerr << "Empty review found at line: " << line << std::endl;
            continue;
        }

        String wreview = String(review.length(), L' ');
        std::copy(review.begin(), review.end(), wreview.begin());
        if (wreview.empty()) {
            std::cerr << "Conversion to wide string resulted in empty string for review: " << review << std::endl;
            continue;
        }

        DocumentPtr document = createDocument(wreview);
        if (!document) {
            std::cerr << "Document creation failed for review: " << review << std::endl;
            continue;
        }

        try {
            indexWriter->addDocument(document);
            num_docs++;
        } catch (const LuceneException& e) {
            std::cerr << "Lucene exception when adding document" << std::endl;
        } catch (const std::exception& e) {
            std::cerr << "Exception when adding document: " << e.what() << std::endl;
        }
    }
    csvFile.close();

    try {
        indexWriter->optimize();
        indexWriter->close();
    } catch (const LuceneException& e) {
        std::cerr << "Lucene exception during optimization or closing" << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Exception during optimization or closing: " << e.what() << std::endl;
    }

    uint64_t finish = rdtsc();
    std::cout << "Done: " << num_docs << " documents ("
              << (finish - start) / CYCLES_PER_US / 1000000.0 << " s)" << std::endl;
}

std::vector<payload> ReadPayloads(const std::string& filename) {
  std::ifstream in(filename, std::ios::binary);
  if (!in.is_open()) {
    std::cerr << "Failed to open file for reading.\n";
    return {};
  }

  std::vector<payload> payloads;
  payload p;
  while (in.read(reinterpret_cast<char*>(&p), sizeof(p))) {
    payloads.push_back(p);
  }

  in.close();
  return payloads;
}

void *luceneWorker(void *arg) {
    int worker_id = *((int *)arg);
    std::string filename = "./loads/" + std::to_string(worker_id) + ".bin";

    // Read payloads from the file
    std::vector<payload> payloads = ReadPayloads(filename);

    // Set up the Lucene searcher
    IndexSearcherPtr searcher = newLucene<IndexSearcher>(dir, true);

    // Perform the search work
    for (const auto& rp : payloads) {
        ldb_tag_set(rp.index);
        uint64_t term_index = rp.term_index;
        uint64_t index = rp.index;

        QueryPtr query = newLucene<TermQuery>(newLucene<Term>(L"contents", StringUtils::toUnicode(std::to_string(term_index))));
        Collection<ScoreDocPtr> hits = searcher->search(query, FilterPtr(), 10)->scoreDocs;
        ldb_tag_clear();
    }

    delete (int *)arg;  // Free the allocated memory
    std::cout << "Worker " << worker_id << " exiting.\n";
    return nullptr;
}

void runServer(int n_threads) {
    std::vector<pthread_t> threads;
    threads.reserve(n_threads);  // Reserve space for the thread handles

    for (int i = 0; i < n_threads; ++i) {
        pthread_t worker_th;
        int* arg = new int(i);  // Allocate memory for the worker ID
        pthread_create(&worker_th, NULL, &luceneWorker, (void*)arg);
        threads.push_back(worker_th);
    }

    // Wait for all threads to complete
    for (pthread_t th : threads) {
        pthread_join(th, NULL);
    }

    std::cout << "All workers have completed.\n";
}

int main(int argc, char *argv[]) {
  if (argc < 2) {
      std::cerr << "Usage: " << argv[0] << " <number_of_threads>\n";
      return 1;
  }

  int n_threads = std::stoi(argv[1]);

  srand(time(NULL));
  
  ReadFreqTerms();
  PopulateIndex();

  logger_reset();
  hrperf_start();
  runServer(n_threads);
  hrperf_pause();
}
