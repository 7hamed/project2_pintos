
---- GRUP ----

>> Grup üyelerinizin isimlerini ve e-posta adreslerini doldurun.
Ahmet Yılmaz <ayilmaz@ogr.deu.edu.tr>
Ayşe Kaya <akaya@ogr.deu.edu.tr>
Mehmet Demir <mdemir@ogr.deu.edu.tr>>

---- AÇIKLAMA ----
>> Pintos dokümantasyonu, ders kitabı, ders notları dışında
>> başvurduğunu ve ders personeliz offline veya online kaynakları belirtin.

Pintos proje dokümantasyonu ve ders notları ana kaynaklarımızdı. Ek olarak, C programlama dili ve işletim sistemleri kavramları hakkında genel çevrimiçi kaynaklardan (örneğin, Stack Overflow, GeeksforGeeks gibi sitelerden belirli konuları anlamak için) faydalandık. Ancak, kod implementasyonları için doğrudan bir dış kaynak kullanılmamıştır, tüm çözümler kendi analizlerimiz ve grup çalışmalarımız sonucunda geliştirilmiştir.
                ARGÜMAN VERME
               ================

---- VERİ YAPILARI --->> A1: Her yeni veya değiştirilen `struct\' ya da `struct\' üyesi, global veya statik değişken, `typedef\' ya da
>> enumerasyonun bildirimini buraya yapın. Her birinin amacını 25 kelimeyle açıklayın.

Argüman verme ve süreç yönetimi kapsamında projemizde aşağıdaki `typedef` kullanılmıştır:

*   `typedef int pid_t;` (syscall.h): Süreç kimliğini (Process ID - PID) temsil etmek için bir tamsayı türü tanımlar. `EXEC` sistem çağrısı bir `pid_t` döndürür ve `WAIT` sistem çağrısı bir `pid_t` alır. Bu, süreçleri yönetmek için standart bir yoldur.

Argümanların kendileri yığın (stack) üzerinde geçirilir ve `process_execute` fonksiyonu içerisinde (detayları `process.c` dosyasındadır) ayrıştırılır. Bu aşamada özel yeni kalıcı veri yapıları (struct\'lar) oluşturulmamıştır; bunun yerine mevcut C tipleri ve işaretçiler kullanılarak yığın manipülasyonu yapılmıştır. Diğer genel amaçlı yapılar (dosya işlemleri için `struct file`, senkronizasyon için `lock_file` vb.) "SİSTEM ÇAĞRILARI" bölümündeki B1 altında detaylandırılmıştır.

---- ALGORİTMALAR ----

>> A2: Argüman ayrıştırmayı nasıl gerçekleştirdiğinizi kısaca açıklayın. 
>> argv[] elemanlarının doğru sırada olmalarını nasıl sağlıyorsunuz?
>> Yığın sayfasının taşmasını nasıl engelliyorsunuz?

Argüman ayrıştırma işlemi, `process.c` dosyasındaki `load()` fonksiyonu içinde, `setup_stack()` çağrısından sonra ve özellikle `make_stack()` yardımcı fonksiyonumuzda gerçekleşir. `process_execute()` fonksiyonu çağrıldığında, komut satırı string'i (`file_name`) kopyalanır. `load()` fonksiyonuna bu kopya iletilir.

`load()` fonksiyonu içerisinde, ilk olarak `strtok_r()` fonksiyonu kullanılarak bu komut satırı string'i boşluklara göre token'lara (argümanlara) ayrılır. Bu token'lar `argv` adında bir karakter dizisi (string) işaretçileri dizisinde saklanır. `strtok_r()` çağrılırken, string'in bir kopyası (`cp_file_name`) üzerinde çalışılır ve her bir token (argüman) `argv` dizisine sırayla eklenir. Bu sayede `argv[]` elemanlarının doğru sırada olması doğal olarak sağlanır, çünkü `strtok_r()` string'i baştan sona doğru işler ve bulduğu token'ları sırayla verir.

Kullanıcı programının yığını (`esp` ile gösterilir) `make_stack()` fonksiyonunda oluşturulur. Argümanlar yığına şu adımlarla yerleştirilir:
1.  Her bir argüman string'i (`argv[i]`) yığına sondan başlanarak (yani `argv[argc-1]`'den `argv[0]`'a doğru) kopyalanır. Her string'in sonuna null terminator (`\0`) eklenir. Bu string'lerin yığındaki adresleri geçici olarak saklanır (`ptr_argv` dizisinde).
2.  Yığının 4 byte'a hizalanması (word-align) için gerekli sayıda padding byte (0 değerinde) eklenir.
3.  `argv[argc]` için standartlara uygun olarak null bir işaretçi (4 byte sıfır) yığına eklenir.
4.  Ardından, saklanan argüman string'lerinin yığındaki adresleri (`ptr_argv[i]`), yine sondan başa doğru (`ptr_argv[argc-1]`'den `ptr_argv[0]`'a) yığına kopyalanır.
5.  `argv` dizisinin başlangıç adresi (yani `char **argv`) yığına kopyalanır.
6.  Argüman sayısı (`argc`) yığına kopyalanır.
7.  Son olarak, sahte bir dönüş adresi (genellikle 0) yığına eklenir.

Yığın sayfasının (Pintos'ta genellikle tek bir sayfa, yani 4KB) taşmasını engellemek için doğrudan bir kontrol mekanizması bu aşamada implemente edilmemiştir. Ancak, `load()` fonksiyonundaki `validate_segment()` ve `load_segment()` fonksiyonları, program segmentlerinin ve başlangıç yığınının kullanıcı adres alanına doğru bir şekilde yerleştirilmesini sağlar. `setup_stack()` fonksiyonu, yığın için tek bir sayfa ayırır. Eğer argümanların toplam boyutu (string'ler, işaretçiler, hizalama ve diğer meta veriler dahil) bu tek sayfayı aşarsa, bu durum bir yığın taşmasına ve tanımsız davranışa yol açabilir. Projemizin bu aşamasında, argümanların makul bir boyutta olacağı varsayılmıştır ve Pintos'un varsayılan yığın boyutu (PHYS_BASE - 1 sayfa) içinde kalınacağı öngörülmüştür. Daha karmaşık bir sistemde, yığın büyüklüğü dinamik olarak ayarlanabilir veya argümanların toplam boyutu için bir üst sınır kontrolü eklenebilirdi.
---- GEREKÇE ----

>> A3: Pintos neden strtok_r() fonksiyonunu implement ederken strtok() fonksiyonunu implement etmemiştir?

Pintos, `strtok_r()` fonksiyonunu implement ederken `strtok()` fonksiyonunu implement etmemiştir çünkü `strtok()` fonksiyonu "reentrant" (yeniden girilebilir) değildir. `strtok()` fonksiyonu, bir string'i token'lara ayırırken, bir sonraki çağrıda nereden devam edeceğini hatırlamak için dahili statik bir işaretçi kullanır. Bu durum, çoklu iş parçacıklı (multi-threaded) bir ortamda veya kesmelerin (interrupts) olduğu bir sistemde sorunlara yol açar. 

Eğer bir iş parçacığı `strtok()` ile bir string'i ayrıştırırken bir kesme meydana gelirse ve kesme hizmet rutini (ISR) veya başka bir iş parçacığı da aynı `strtok()` fonksiyonunu farklı bir string ile çağırırsa, `strtok()`'ın dahili statik işaretçisinin üzerine yazılır. İlk iş parçacığı çalışmaya devam ettiğinde, yanlış yerden devam eder ve bu da hatalı sonuçlara veya programın çökmesine neden olabilir.

`strtok_r()` (reentrant version of strtok) ise bu sorunu çözer. `strtok_r()`, kullanıcı tarafından sağlanan bir `char **saveptr` (veya benzeri bir isimde) işaretçi aracılığıyla kendi durumunu (bir sonraki token'ın başlangıç pozisyonu) saklar. Bu sayede, her `strtok_r()` çağrısı kendi bağlamını korur ve farklı iş parçacıkları veya kesme rutinleri aynı anda `strtok_r()` fonksiyonunu farklı string'ler üzerinde güvenle kullanabilir. Pintos gibi bir işletim sistemi çekirdeği, eşzamanlılık ve kesme yönetimi gibi karmaşık durumlarla başa çıkmak zorunda olduğu için, `strtok_r()` gibi yeniden girilebilir fonksiyonlar tercih edilir. Bu, sistemin kararlılığını ve güvenilirliğini artırır.
>> A4: Pintos'ta, çekirdek komutları çalıştırılabilir bir ad ve argümanlar olarak ayırır. Unix benzeri sistemlerde, kabuk bu ayrımı yapar.
>> Unix yaklaşımının en az iki avantajını belirtin.

Unix benzeri sistemlerde kabuğun (shell) komutları ve argümanları ayırmasının Pintos'taki çekirdek tabanlı yaklaşıma göre bazı avantajları vardır:

1.  **Esneklik ve Kullanıcı Deneyimi:** Kabuklar, kullanıcıya komut tamamlama, geçmiş (history), takma adlar (alias), boru hatları (pipelines `|`), I/O yönlendirmesi (`>`, `<`, `>>`) gibi zengin özellikler sunar. Bu özellikler, komut satırı arayüzünü çok daha güçlü ve kullanıcı dostu hale getirir. Kullanıcılar, farklı kabuklar (bash, zsh, fish vb.) arasından kendi ihtiyaçlarına en uygun olanı seçebilirler. Çekirdeğin bu işlevselliği sağlaması, çekirdeği gereksiz yere karmaşıklaştırır ve bu tür kullanıcı arayüzü özelliklerini geliştirmeyi zorlaştırır.

2.  **Ayrım ve Güvenlik:** Kabuğun kullanıcı modunda ayrı bir süreç olarak çalışması, görevlerin net bir şekilde ayrılmasını sağlar. Komut ayrıştırma ve yorumlama gibi karmaşık ve potansiyel olarak hata eğilimli işlemler kullanıcı modunda gerçekleşir. Eğer kabukta bir hata oluşursa (örneğin, hatalı bir komut ayrıştırması nedeniyle), bu genellikle sadece kabuk sürecini etkiler ve çekirdeğin kararlılığını tehlikeye atmaz. Çekirdek bu işleri yaptığında, çekirdekteki bir hata tüm sistemi çökertebilir. Bu ayrım, sistemin genel güvenliğini ve kararlılığını artırır. Ayrıca, kabuk, kullanıcıdan gelen girdiyi çekirdeğe iletmeden önce bir filtreleme ve doğrulama katmanı görevi de görebilir.

Unix yaklaşımı, bu sayede daha modüler, genişletilebilir ve sağlam bir sistem mimarisi sunar.
                 SİSTEM ÇAĞRILARI
                 ============

---- VERİ YAPILARI ----
>> B1: Her yeni veya değiştirilen `struct` ya da `struct` üyesi, global veya statik değişken, `typedef` ya da
>> enumerasyonun bildirimini buraya yapın. Her birinin amacını 25 kelimeyle açıklayın.

Sistem çağrıları implementasyonu kapsamında aşağıdaki yeni veya değiştirilmiş veri yapıları, global/statik değişkenler ve typedef\'ler kullanılmıştır:

*   `typedef int pid_t;` (syscall.h): Bu typedef, A1 bölümünde de belirtildiği gibi, süreç kimliklerini (PID) temsil eder. `EXEC` ve `WAIT` gibi sistem çağrılarında süreçleri tanımlamak için kullanılır.
*   `extern struct lock lock_file;` (syscall.h) ve `struct lock lock_file;` (syscall.c): Dosya sistemi ile ilgili sistem çağrılarında (örneğin, `OPEN`, `READ`, `WRITE`, `CLOSE`) eşzamanlı erişimi yönetmek ve yarış koşullarını önlemek için kullanılan global bir kilittir. Dosya işlemlerinin atomik olmasını sağlar.
*   `struct file` (syscall.c içinde tanımlı, ancak filesys/file.h\deki struct file\'a atıfta bulunur): Açık bir dosyayı temsil eden yapıdır. Genellikle bir inode işaretçisi, dosyadaki mevcut pozisyon (offset) ve dosyanın yazmaya karşı kilitli olup olmadığını belirten bir bayrak (`deny_write`) içerir. Her bir dosya tanımlayıcısı bu tür bir yapıya işaret eder.
*   `thread` yapısındaki değişiklikler (threads/thread.h içinde, dolaylı olarak syscall.c\'yi etkiler):
    *   `int exit_status;`: Bir thread\'in (sürecin) çıkış durumunu saklamak için eklenmiştir. `EXIT` sistem çağrısında ayarlanır ve `WAIT` tarafından okunur.
    *   `struct file *FD[128];`: Her bir thread için bir dosya tanımlayıcı (File Descriptor) tablosu. Bu dizi, sürecin açık dosyalarını tutar. İndeks, dosya tanımlayıcısını temsil eder ve değer, karşılık gelen `struct file` işaretçisidir. 0, 1, 2 standart giriş/çıkış/hata için ayrılmıştır.
    *   `struct list child_list;`: Bir thread\'in (ebeveyn) sahip olduğu çocuk süreçlerin listesini tutar. `EXEC` ile çocuk süreç oluşturulduğunda bu listeye eklenir.
    *   `struct list_elem child_elem;`: Bir thread\'in, ebeveyninin `child_list`\'inde yer almasını sağlayan liste elemanıdır.
    *   `struct semaphore load_lock;`: `EXEC` sistem çağrısında, ebeveyn sürecin çocuk sürecin yüklenmesini beklemesi için kullanılır. Yükleme tamamlandığında veya başarısız olduğunda serbest bırakılır.
    *   `struct semaphore child_lock;`: `WAIT` sistem çağrısında, ebeveyn sürecin çocuk sürecin sonlanmasını beklemesi için kullanılır. Çocuk süreç sonlandığında serbest bırakılır.
    *   `struct semaphore mem_lock;`: Çocuk süreç sonlandığında ve ebeveyn `WAIT` ile durumunu aldığında, çocuğun `thread` yapısının güvenli bir şekilde serbest bırakılmasını senkronize etmek için kullanılır.
*   `static void syscall_handler (struct intr_frame *);` (syscall.c): Sistem çağrısı kesmesi (0x30) için ana işleyici fonksiyondur. Kullanıcı yığınından sistem çağrısı numarasını ve argümanlarını okur, ilgili fonksiyonu çağırır.
*   `#define VERIFY_ADDR(ADDR)` (syscall.c): Kullanıcı tarafından sağlanan bir sanal adresin geçerli bir kullanıcı adresi olup olmadığını ve null olup olmadığını kontrol eden bir makrodur. Geçersizse, süreci -1 durumuyla sonlandırır.

Bu yapılar ve değişkenler, sistem çağrılarının doğru ve güvenli bir şekilde çalışması için temel oluşturur.

>> B2: Dosya tanımlayıcılarının açık dosyalarla nasıl ilişkilendirildiğini açıklayın.
>> Dosya tanımlayıcıları tüm işletim sistemi genelinde mi yoksa yalnızca tek bir işlemde mi benzersizdir?

Projemizde, dosya tanımlayıcıları (file descriptors - FD) açık dosyalarla her bir süreç (thread) bazında ilişkilendirilmiştir. Her `thread` yapısı içerisinde `struct file *FD[128];` şeklinde bir dizi bulunur. Bu dizi, o sürece ait dosya tanımlayıcı tablosu olarak görev yapar.

Bir dosya `OPEN` sistem çağrısı ile açıldığında, çekirdek `filesys_open()` fonksiyonunu kullanarak dosyayı açar ve bu açık dosyayı temsil eden bir `struct file` işaretçisi elde eder. Daha sonra, o sürece ait `FD` tablosunda boş bir yer (NULL olan bir giriş) aranır. Genellikle 3. indeksten başlanarak (0, 1 ve 2 standart giriş, çıkış ve hata için ayrılmıştır) uygun bir boşluk bulunduğunda, bu indekse (yani dosya tanımlayıcısına) açık dosyanın `struct file` işaretçisi atanır. `OPEN` sistem çağrısı da bu indeksi (dosya tanımlayıcısını) kullanıcı programına döndürür.

Örneğin, `syscall.c` içerisindeki `OPEN` fonksiyonunda şu mantık işler:
```c
// ... (dosya adı kontrolü ve kilit alma)
struct file *f = filesys_open(file);
// ... (f null ise hata yönetimi)
FOR_RANGE(i, 3, 128) { // 3'ten 127'ye kadar boş FD ara
    if (!thread_current()->FD[i]) { // Eğer FD[i] boşsa
        // ... (gerekirse yazma engelleme)
        thread_current()->FD[i] = f; // FD'ye struct file* ata
        // ... (kilit bırakma ve i değerini döndürme)
        return res = i;
    }
}
// ... (boş FD bulunamazsa hata yönetimi)
```
Sonraki `READ`, `WRITE`, `CLOSE`, `FILESIZE`, `SEEK`, `TELL` gibi dosya işlemleri, kullanıcı programından aldıkları dosya tanımlayıcısını (örneğin `fd`) kullanarak `thread_current()->FD[fd]` üzerinden ilgili `struct file` işaretçisine erişir ve dosya sistemi fonksiyonlarını (örneğin `file_read()`, `file_write()`) bu işaretçi ile çağırır.

Dosya tanımlayıcıları **yalnızca tek bir işlemde (süreçte) benzersizdir**. Farklı süreçler aynı dosya tanımlayıcı numarasını (örneğin, FD 3) kullanabilirler, ancak bu numaralar kendi süreçlerine ait farklı açık dosyalara (veya aynı dosyaya ait farklı açık durumlara) işaret eder. Her sürecin kendi özel `FD` tablosu olduğu için, bir sürecin FD 3'ü, başka bir sürecin FD 3'ünden tamamen bağımsızdır. İşletim sistemi genelinde benzersiz değillerdir. Ancak, her bir açık dosya örneği (yani `struct file` nesnesi) sistem genelinde benzersiz bir kaynağı temsil edebilir (örneğin, aynı fiziksel dosyaya işaret eden farklı `struct file` nesneleri olabilir, her biri kendi pozisyon bilgisine sahip).

---- ALGORİTMALAR ----

>> B3: Çekirdekten kullanıcı verilerini okuma ve yazma kodunuzu açıklayın.

Çekirdekten kullanıcı verilerine (kullanıcı adres alanındaki verilere) erişmek, dikkatli bir şekilde yapılmalıdır çünkü kullanıcı tarafından sağlanan işaretçiler geçersiz olabilir (örneğin, haritalanmamış bir alana işaret edebilir, çekirdek alanına işaret edebilir veya null olabilir). Bu tür geçersiz erişimler sistemin çökmesine neden olabilir. Bu nedenle, bu tür erişimleri güvenli bir şekilde yapmak için mekanizmalar geliştirdik.

**1. Adres Doğrulama:**
Kullanıcıdan gelen herhangi bir işaretçiyi (adres) kullanmadan önce, bu adresin geçerli bir kullanıcı sanal adresi olup olmadığını kontrol ederiz. `syscall.c` dosyamızda `VERIFY_ADDR(ADDR)` adında bir makro tanımladık:
```c
#define VERIFY_ADDR(ADDR) \
    do { \
        if (!is_user_vaddr(ADDR)) EXIT(-1); \
    } while(0)
```
Bu makro, Pintos'un `is_user_vaddr()` fonksiyonunu (verilen adresin kullanıcı adres alanında olup olmadığını kontrol eder) ve ayrıca adresin `NULL` olup olmadığını (örtük olarak `is_user_vaddr` içinde veya ek bir kontrolle) kontrol eder. Eğer adres geçersizse, `EXIT(-1)` çağrılarak mevcut süreç -1 çıkış durumuyla sonlandırılır. Bu makro, sistem çağrısı argümanları olarak alınan tüm işaretçiler için `syscall_handler` içinde ve ayrıca `READ` ve `WRITE` gibi sistem çağrılarının implementasyonlarında tampon adresleri için kullanılır.

Örneğin, `SYS_EXIT` çağrısında:
```c
case SYS_EXIT:
  VERIFY_ADDR(f->esp + 4); // status argümanının adresini doğrula
  EXIT(*(uint32_t *)(f->esp + 4));
  break;
```
Ve `READ` sistem çağrısında tampon adresi için:
```c
int READ (int fd, void *buffer, unsigned size) {
  if(!buffer) EXIT(-1); // Buffer null mı diye ek kontrol
  VERIFY_ADDR(buffer); // Buffer adresi geçerli kullanıcı adresi mi?
  // ... (okuma işlemleri)
}
```

**2. Sayfa Hatalarını Yönetme (Dolaylı Yöntem):**
Pintos'ta, kullanıcı adres alanına yapılan bir erişim, eğer o adres haritalanmamışsa veya erişim hakları ihlal ediliyorsa bir sayfa hatasına (#PF) neden olur. `exception.c` dosyasındaki `page_fault()` işleyicisi bu hataları yakalar.

Projemizin bu aşamasında, `page_fault()` işleyicisi, kullanıcı modunda meydana gelen ve geçerli olmayan bir adrese (örneğin, haritalanmamış veya çekirdek alanına) erişimden kaynaklanan sayfa hatalarını tespit ettiğinde süreci sonlandıracak şekilde basitleştirilmiştir. `exception.c` içindeki `page_fault` fonksiyonunda şu şekilde bir kontrol ekledik:
```c
// ... (fault_addr, user, not_present gibi değişkenler alınır)
if (is_kernel_vaddr(fault_addr) || !user || not_present) {
  EXIT(-1); // Çekirdek adresine erişim, kernel modunda hata veya sayfa yoksa sonlandır
}
```
Bu, çekirdeğin kullanıcı verilerine erişmeye çalışırken (örneğin `READ` veya `WRITE` sırasında `memcpy` gibi bir fonksiyonla) eğer kullanıcı tarafından sağlanan tampon adresi sayfa sayfa geçerli olsa bile, tamponun bir kısmı haritalanmamış bir alana denk gelirse, oluşacak sayfa hatasının süreci sonlandırmasını sağlar. Bu, doğrudan bir "bayt bayt güvenli okuma/yazma" fonksiyonu yerine, donanımın sayfa hatası mekanizmasına güvenerek dolaylı bir güvenlik sağlar.

**3. Veri Kopyalama:**
Gerçek veri okuma ve yazma işlemleri için standart C fonksiyonları (örneğin `memcpy`, veya döngülerle bayt bayt kopyalama) kullanılır. Ancak bu fonksiyonlar çağrılmadan önce yukarıdaki adres doğrulama mekanizmaları sayesinde işaretçilerin en azından başlangıç noktalarının geçerli kullanıcı adresleri olduğu varsayılır. Eğer kopyalama sırasında haritalanmamış bir alana denk gelinirse, sayfa hatası oluşur ve süreç sonlandırılır.

`WRITE` sistem çağrısında, kullanıcıdan gelen `buffer`'dan konsola veya dosyaya yazarken, `putbuf()` (konsol için) veya `file_write()` (dosya için) fonksiyonları kullanılır. Bu fonksiyonlar, verilen `buffer` işaretçisinden veriyi okur. `READ` sistem çağrısında ise, dosyadan veya konsoldan okunan veri, kullanıcı tarafından sağlanan `buffer`'a yazılır (`input_getc()` veya `file_read()` ile).

Bu yaklaşım, her bayt erişimini ayrı ayrı kontrol etmek yerine, sayfa tabanlı koruma mekanizmalarına ve başlangıç adres doğrulamasına dayanır. Daha gelişmiş sistemlerde, çekirdek, kullanıcı belleğine erişmek için özel "güvenli kopyalama" rutinleri kullanabilir (örneğin, `copy_from_user` / `copy_to_user`), bu rutinler her erişimi dikkatlice kontrol eder ve sayfa hatalarını daha zarif bir şekilde yönetebilir.
>> B4: Bir sistem çağrısı, kullanıcı alanından çekirdeğe 4,096 baytlık bir veriyi kopyalıyorsa, 
>> bu sayfa tablosunun (örneğin pagedir_get_page() çağrıları) en az ve en fazla kaç kere denetlenmesi gerektiğini açıklayın.
>> Peki, yalnızca 2 baytlık veriyi kopyalayan bir sistem çağrısı için nasıl bir durum olur? Bu sayılar üzerinde iyileştirme yapılabilir mi?

Açıklama:
Pintos'ta sayfa boyutu 4096 bayttır (4KB). `pagedir_get_page()` gibi bir fonksiyon, verilen bir sanal adres için sayfa tablosu girişini bulur, adresin geçerliliğini (haritalı olup olmadığı, kullanıcı/çekirdek modu, okuma/yazma izinleri) kontrol eder. Bir veri bloğu kopyalanırken, bu bloğun kapsadığı her bir sanal sayfanın geçerliliği kontrol edilmelidir.

**Durum 1: 4,096 baytlık veri kopyalama (tam bir sayfa boyutu)**

*   **En Az Denetleme Sayısı: 1**
    Eğer 4,096 baytlık tampon bellek adresi bir sayfa sınırına hizalıysa (örneğin, `0xUSER_PAGE_START` adresinden başlayıp `0xUSER_PAGE_START + 4095` adresinde bitiyorsa), tüm tampon tek bir sanal sayfa içinde yer alır. Bu durumda, bu tek sayfanın geçerliliğini kontrol etmek için `pagedir_get_page()` gibi bir fonksiyonun **bir kez** çağrılması yeterlidir.

*   **En Fazla Denetleme Sayısı: 2**
    Eğer 4,096 baytlık tampon bellek adresi bir sayfa sınırına hizalı değilse, iki sanal sayfaya yayılabilir. Örneğin, tampon bir sayfanın ortasından başlayıp bir sonraki sayfanın bir kısmını kapsayacak şekilde olabilir (örneğin, ilk sayfanın son baytından başlayıp sonraki sayfanın 4095 baytını kullanırsa veya ilk sayfanın ilk baytından farklı bir yerden başlayıp bir sonraki sayfaya taşarsa).
    Örnek: Tampon `0xUSER_PAGE_START + 1` adresinden başlarsa, `0xUSER_PAGE_START + 1` ile `0xUSER_PAGE_START + 4095` (ilk sayfada 4095 bayt) ve `0xUSER_PAGE_START + 4096` (ikinci sayfada 1 bayt) adreslerini kapsar. Bu durumda, her iki sayfanın da ayrı ayrı kontrol edilmesi gerekir, yani `pagedir_get_page()` **iki kez** çağrılır.

**Durum 2: 2 baytlık veri kopyalama**

*   **En Az Denetleme Sayısı: 1**
    Eğer 2 baytlık tamponun tamamı tek bir sanal sayfa içinde yer alıyorsa (ki bu her zaman mümkündür çünkü 2 bayt << 4096 bayt), bu sayfanın geçerliliğini kontrol etmek için `pagedir_get_page()` **bir kez** çağrılır.

*   **En Fazla Denetleme Sayısı: 2**
    Eğer 2 baytlık tampon bir sayfa sınırına denk geliyorsa, yani ilk baytı bir sayfanın son baytı ve ikinci baytı bir sonraki sayfanın ilk baytı ise, tampon iki farklı sanal sayfaya yayılır. Örneğin, ilk bayt `0xUSER_PAGE_END` adresinde ve ikinci bayt `0xUSER_PAGE_END + 1` (bir sonraki sayfanın başlangıcı) adresinde ise. Bu durumda, her iki sayfanın da ayrı ayrı kontrol edilmesi gerekir, yani `pagedir_get_page()` **iki kez** çağrılır.

**Bu Sayılar Üzerinde İyileştirme Yapılabilir mi?**

Bu denetleme sayıları, kopyalanan verinin kaç farklı sanal sayfaya yayıldığına bağlıdır ve her bir sayfanın güvenli erişim için doğrulanması gerektiği prensibine dayanır. Bu nedenle, mantıksal denetleme sayısı (yani kaç farklı sayfanın kontrol edilmesi gerektiği) genellikle azaltılamaz.

Ancak, "iyileştirme" şu şekillerde düşünülebilir:
1.  **Denetleme Verimliliği:** Her bir `pagedir_get_page()` çağrısının hızı, TLB (Translation Lookaside Buffer) isabetleri ile artırılabilir. Eğer sayfa tablosu bilgisi TLB'de ise, tam sayfa tablosu yürümesi gerekmez. Ancak bu, çağrı sayısını değil, her çağrının maliyetini azaltır.
2.  **Kodlama Stratejisi:** Eğer çekirdek, `VERIFY_ADDR` ile sadece tamponun başlangıç adresini kontrol edip ardından `memcpy` gibi bir fonksiyonla kopyalama yapar ve sayfa sınırlarını aşan geçersiz erişimler için sayfa hatası mekanizmasına güvenirse, *açık* `pagedir_get_page()` çağrı sayısı azalabilir (belki sadece başlangıç için 1). Ancak bu, daha az proaktif bir güvenlik modelidir ve sayfa hatalarını yakalayıp uygun şekilde yönetmeyi gerektirir. Sorunun "denetlenmesi" ifadesi, proaktif bir kontrolü ima etmektedir.
3.  **Büyük Sayfalar (Huge Pages):** Eğer işletim sistemi 4KB'den daha büyük sayfaları (örneğin, 2MB) destekliyorsa, küçük tamponlar (4KB veya 2 byte gibi) her zaman tek bir büyük sayfa içine sığar ve denetleme sayısı 1'e düşebilir. Ancak Pintos varsayılan olarak 4KB sayfalar kullanır.

Sonuç olarak, her erişilen sanal sayfanın en az bir kez doğrulanması gerektiği düşünüldüğünde, yukarıda belirtilen en az ve en fazla denetleme sayıları temeldir ve mantıksal olarak iyileştirilmesi zordur. İyileştirmeler daha çok her bir denetimin verimliliği veya hata yönetimi stratejileriyle ilgilidir.

>> B5: "wait" sistem çağrısının implementasyonunu kısaca açıklayın ve işlem sonlandırma ile nasıl etkileşime girdiğini belirtin.

`WAIT(pid_t pid)` sistem çağrısı, çağıran ebeveyn sürecin, `pid` ile belirtilen çocuk sürecinin sonlanmasını beklemesini sağlar. Çocuk süreç sonlandığında, ebeveyn süreç çocuğun çıkış durumunu (exit status) alır ve çalışmasına devam eder.

**Implementasyonumuz (`process.c` içindeki `process_wait(tid_t child_tid)` fonksiyonu):**

1.  **Çocuk Süreci Bulma:** Ebeveyn sürecin (`thread_current()`) `child_list` adlı listesinde, verilen `child_tid`'ye sahip çocuk süreç aranır. Bu liste, `EXEC` ile çocuk süreç oluşturulduğunda güncellenir ve her çocuk `thread` yapısı bu listeye `child_elem` ile eklenir.
    ```c
    struct thread *cur = thread_current();
    struct thread *child = NULL;
    // ...
    struct list_elem *e;
    FOR_LIST(e, &(cur->child_list)) {
        child = list_entry(e, struct thread, child_elem);
        if (child->tid == child_tid) { 
            // Çocuk bulundu
            break;
        }
    }
    ```
2.  **Bekleme (Senkronizasyon):** Eğer çocuk süreç bulunursa, ebeveyn süreç bu çocuğa ait `child_lock` adlı bir semafor üzerinde `sema_down()` yaparak beklemeye geçer. Bu semafor, çocuk süreç oluşturulurken başlatılır (genellikle 0 değeriyle).
    ```c
    // Çocuk bulunduktan sonra:
    sema_down(&(child->child_lock)); // Çocuğun sonlanmasını bekle
    ```
3.  **Çıkış Durumunu Alma ve Kaynakları Temizleme:** Çocuk süreç sonlandığında (`process_exit()` içinde), kendi `child_lock` semaforunu `sema_up()` yaparak ebeveynini uyandırır. Ebeveyn uyandığında, çocuğun `exit_status` değerini alır. Ardından, çocuk sürece ait `child_elem`'i kendi `child_list`'inden çıkarır. Son olarak, çocuğun `thread` yapısının güvenle serbest bırakılabilmesi için çocuğa ait `mem_lock` semaforunu `sema_up()` yapar (çocuk `process_exit` sonunda bu semaforu `sema_down` ile bekliyor olabilir).
    ```c
    // Ebeveyn uyandıktan sonra:
    exit_status = child->exit_status;
    list_remove(&(child->child_elem)); // Çocuğu ebeveynin listesinden çıkar
    sema_up(&(child->mem_lock));      // Çocuğun kendi kaynaklarını serbest bırakmasına izin ver
    ```
4.  **Geçersiz Durumlar:** Eğer `child_tid` geçerli bir çocuk değilse (listede bulunamazsa) veya `wait` aynı çocuk için daha önce çağrılıp başarılı olduysa (çocuk listeden çıkarıldığı için bulunamaz), `process_wait` hemen -1 döndürür.

**İşlem Sonlandırma ile Etkileşim (`process_exit()` fonksiyonu):**

Bir süreç (ister ebeveyn ister çocuk) sonlandığında `process_exit()` fonksiyonu çağrılır. Bu fonksiyon, `WAIT` mekanizmasıyla şu şekillerde etkileşir:
1.  **Çıkış Durumunu Kaydetme:** Süreç, `thread_current()->exit_status` alanına kendi çıkış durumunu kaydeder. Bu, `EXIT(status)` sistem çağrısı tarafından yapılır.
2.  **Ebeveyni Uyandırma:** Süreç, kendi `child_lock` semaforunu `sema_up()` yaparak, eğer varsa kendisini bekleyen ebeveyn süreci uyandırır.
    ```c
    // process_exit() içinde:
    sema_up(&(cur->child_lock)); // Beni bekleyen ebeveyni uyandır
    ```
3.  **Kaynakların Serbest Bırakılmasını Bekleme:** Süreç, ebeveyni tarafından `WAIT` çağrısı ile çıkış durumu alınıp `mem_lock` semaforu serbest bırakılana kadar kendi `thread` yapısını ve diğer kaynaklarını tamamen serbest bırakmadan önce `sema_down(&(cur->mem_lock))` ile bekler. Bu, ebeveynin, çocuk sonlandıktan sonra bile çocuğun çıkış durumuna güvenli bir şekilde erişebilmesini sağlar.

Bu senkronizasyon mekanizmaları (semaforlar: `child_lock` ve `mem_lock`), ebeveyn ve çocuk süreçler arasında `wait` ve `exit` işlemlerinin doğru bir şekilde sıralanmasını ve yarış koşullarının önlenmesini sağlar. Ebeveyn, çocuk sonlanana kadar bekler; çocuk sonlandığında ebeveyni bilgilendirir ve ebeveyn durumu aldıktan sonra çocuğun kaynakları güvenle temizlenir.

>> B6: Kullanıcı t>> B6: Kullanıcı tarafından belirtilen bir adreste kullanıcı programı belleğine yapılacak her erişim, kötü bir işaretçi değeri nedeniyle başarısız olabilir.
>> Bu tür erişimlerin işlem sonlandırılmasına yol açması gerekir. Sistem çağrıları bu tür erişimlerle doludur, örneğin "write" sistem çağrısı,
>> sistem çağrısı numarasını kullanıcı yığından okumayı, ardından çağrının üç argümanını, sonrasında ise her türlü kullanıcı belleğini okumayı gerektirir
>> ve bunların herhangi biri herhangi bir noktada başarısız olabilir. Bu, tasarım ve hata yönetimi sorunu oluşturur: hata yönetiminin
>> kodun asıl işlevini gölgelemesini nasıl engellersiniz? Ayrıca, bir hata tespit edildiğinde, geçici olarak tahsis edilen tüm kaynakların
>> (kilitler, tamponlar vb.) serbest bırakılmasını nasıl sağlarsınız? Birkaç paragrafta, bu sorunları yönetmek için benimsediğiniz stratejiyi açıklayın.
>> Bir örnek verin.

Kullanıcı tarafından sağlanan adreslerin geçersiz olabileceği (null, haritalanmamış, çekirdek alanına ait vb.) ve bu durumların süreci sonlandırması gerektiği bilinciyle sistem çağrılarımızı tasarladık. Bu tür hataları yönetmek ve kodun asıl işlevini gölgelememek için benimsediğimiz strateji birkaç katmandan oluşur:

1.  **Proaktif Adres Doğrulama (VERIFY_ADDR Makrosu):**
    Sistem çağrısı işleyicisine (`syscall_handler`) girildiğinde, kullanıcı yığınından okunan sistem çağrısı argümanları (işaretçiler dahil) için ilk olarak `VERIFY_ADDR()` makromuzu kullanırız. Bu makro, B3 bölümünde açıklandığı gibi, adresin geçerli bir kullanıcı sanal adresi olup olmadığını kontrol eder. Eğer adres geçersizse, makro doğrudan `EXIT(-1)` çağırarak süreci sonlandırır. Bu, birçok hatalı durumu sistem çağrısının ana mantığına girmeden önce yakalar.
    *Örnek:* `SYS_CREATE` çağrısında dosya adı işaretçisi ve `SYS_READ` çağrısında tampon işaretçisi bu makro ile kontrol edilir.
    Bu yaklaşım, hata yönetimini ana işlevden bir nebze ayırır, çünkü doğrulama ayrı bir makro ile yapılır ve başarısızlık durumunda fonksiyonun geri kalanı çalıştırılmaz.

2.  **Donanım Tabanlı Koruma (Sayfa Hataları):**
    Başlangıç adres doğrulaması geçilse bile, bir tamponun tamamı geçerli olmayabilir (örneğin, tampon bir sayfa sınırını aşıp haritalanmamış bir alana taşabilir). Bu durumda, çekirdek kullanıcı belleğine erişmeye çalıştığında (örneğin `memcpy` veya `file_read` ile kullanıcı tamponuna yazarken) bir sayfa hatası (#PF) oluşur.
    `exception.c` dosyasındaki `page_fault()` işleyicimiz, kullanıcı modundan kaynaklanan ve geçersiz bir erişim (not-present page, kernel space access from user mode) sonucu oluşan sayfa hatalarında süreci `EXIT(-1)` ile sonlandıracak şekilde düzenlenmiştir. Bu, çekirdeğin kendisinin çökmesini engeller ve hatalı süreci temiz bir şekilde bitirir.
    Bu mekanizma, her baytı manuel olarak kontrol etme yükünü azaltır ve donanımın sağladığı korumaya güvenir. Hata yönetimi, ana sistem çağrısı kodundan ziyade sayfa hatası işleyicisine devredilmiş olur.

3.  **Erken Çıkış ve Kaynak Yönetimi:**
    Bir hata tespit edildiğinde (ister `VERIFY_ADDR` ile ister bir dosya işlemi hatasıyla), genellikle ilgili sistem çağrısı fonksiyonundan erken çıkış yapılır ve uygun bir hata değeri (genellikle -1) döndürülür veya süreç `EXIT(-1)` ile sonlandırılır.
    Geçici olarak tahsis edilen kaynakların (özellikle kilitler) serbest bırakılması kritik öneme sahiptir. Stratejimiz şöyledir:
    *   **Kilitler:** Dosya sistemi işlemleri gibi paylaşılan kaynaklara erişimden önce `lock_acquire(&lock_file)` ile bir kilit alınır. Fonksiyonun normal veya hatalı her çıkış yolunda bu kilidin `lock_release(&lock_file)` ile serbest bırakılması sağlanır. Bu, genellikle `goto done;` gibi bir yapı ve fonksiyon sonunda tek bir serbest bırakma noktası ile veya her çıkış noktasından önce manuel olarak serbest bırakma ile yapılır. Bizim `syscall.c` implementasyonumuzda, kilit genellikle bir işlem bloğunun başında alınıp sonunda bırakılır. Eğer `EXIT(-1)` çağrılırsa, süreç sonlanacağı için kilitlerin durumu işletim sisteminin genel temizlik mekanizmalarına kalır (ancak idealde `EXIT` öncesi de bırakılmalıdır, bizim kodumuzda `EXIT` çağrısı kilidi otomatik bırakmaz, bu bir iyileştirme alanı olabilir).
        *Örnek:* `OPEN` fonksiyonunda, `lock_acquire` çağrısından sonra, dosya bulunamazsa veya FD ayrılamazsa, `lock_release` çağrılır ve sonra -1 döndürülür.
        ```c
        // OPEN içinde bir hata durumu örneği
        if (!f) { // filesys_open başarısız
            lock_release(&lock_file);
            return res; // res = -1
        }
        ```
    *   **Bellek Tahsisleri:** `palloc_get_page()` ile tahsis edilen bellek (örneğin `process_execute` içindeki `fn_copy`), hata durumunda veya işi bittiğinde `palloc_free_page()` ile serbest bırakılır. Bu, genellikle `goto done;` ve `done:` etiketinde bir temizlik bölümü ile yönetilir.

4.  **Fonksiyonların Atomikliği ve Hata Bildirimi:**
    Sistem çağrıları mümkün olduğunca atomik davranacak şekilde tasarlanmaya çalışılır. Yani, ya işlem tamamen başarılı olur ya da bir hata durumunda sistem tutarlı bir durumda kalır ve yapılan değişiklikler (mümkünse) geri alınır veya en azından daha fazla bozulma önlenir. Hatalar, genellikle kullanıcı programına -1 gibi bir dönüş değeri ile bildirilir.

**Örnek Senaryo: `WRITE` Sistem Çağrısı**
1.  `syscall_handler`, `SYS_WRITE` için argümanların (fd, buffer, size) adreslerini yığından okur. Bu okuma sırasında `f->esp + X` adresleri için `VERIFY_ADDR` kullanılmazsa (bizim kodumuzda `syscall_handler` içindeki switch case'lerde argüman adresleri için `VERIFY_ADDR` kullanılıyor), ilk hata burada oluşabilir. Eğer kullanılıyorsa, geçersiz bir yığın işaretçisi süreci sonlandırır.
2.  `WRITE` fonksiyonu çağrılır. `buffer` işaretçisi `VERIFY_ADDR(buffer)` ile kontrol edilir. Geçersizse, `EXIT(-1)`.
3.  Eğer `fd == 1` (stdout) ise, `putbuf(buffer, size)` çağrılır. `putbuf` içinde `buffer` okunurken bir sayfa hatası oluşursa, `page_fault` işleyicisi süreci sonlandırır.
4.  Eğer `fd > 2` (dosya) ise, `thread_current()->FD[fd]` kontrol edilir. Geçersizse `EXIT(-1)`.
5.  `lock_acquire(&lock_file)` çağrılır.
6.  `file_write()` çağrılır. Bu fonksiyon `buffer`'ı okurken bir sayfa hatası oluşursa, süreç sonlanır. Eğer `file_write` başka bir nedenle (örn. disk dolu) başarısız olursa, bir hata kodu döndürür.
7.  `lock_release(&lock_file)` çağrılır.
8.  Sonuç kullanıcıya döndürülür.

Bu strateji, hata yönetimini kodun ana akışından mümkün olduğunca ayırmaya çalışır (`VERIFY_ADDR`, sayfa hatası işleyicisi) ve kaynakların (özellikle kilitlerin) her durumda serbest bırakılmasını sağlamaya odaklanır. Ancak, her `EXIT(-1)` çağrısından önce tüm yerel kaynakların (örneğin o an tutulan kilitler) manuel olarak serbest bırakılması, kodun daha sağlam olmasını sağlar; bizim mevcut `EXIT` implementasyonumuz bunu otomatik yapmaz, bu bir eksiklik olarak görülebilir.

>> B7: "exec" sistem çağrısı, yeni çalıştırılabilir dosya yüklenirse -1 döner, bu nedenle yeni çalıştırılabilir dosya yüklenmeden önce dönemez.
>> Kodunuz bunun nasıl sağlandığını nasıl garanti eder? Yükleme başarı/durum bilgisini "exec" çağrısını yapan işleme nasıl iletirsiniz?

`EXEC(const char *cmd_line)` sistem çağrısının, yeni çalıştırılabilir dosyanın yüklenmesi başarısız olursa -1 döndürmesi ve yükleme işlemi tamamlanmadan (başarılı veya başarısız) dönmemesi, ebeveyn süreç ile oluşturulan çocuk süreç arasında dikkatli bir senkronizasyon ile sağlanır. Bu mekanizma temel olarak `process.c` içerisindeki `process_execute()` ve `start_process()` fonksiyonları ile `thread` yapısına eklediğimiz bir semafor (`load_lock`) ve `exit_status` alanı aracılığıyla çalışır.

**1. Yükleme Tamamlanmadan Dönmemesinin Garanti Edilmesi:**

*   `EXEC` sistem çağrısı `process_execute(cmd_line)` fonksiyonunu çağırır.
*   `process_execute()` içinde, yeni bir thread (çocuk süreç) `thread_create()` ile oluşturulur. Bu yeni thread `start_process()` fonksiyonunu çalıştıracaktır.
*   Çocuk süreç `thread` yapısına `load_lock` adında bir semafor ekledik. Bu semafor, çocuk süreç oluşturulurken 0 değeriyle başlatılır.
*   `process_execute()` (ebeveyn bağlamında çalışır), çocuk thread oluşturulduktan ve çocuğun `thread` yapısı ebeveynin `child_list`'ine eklendikten sonra, çocuğa ait `load_lock` semaforunda `sema_down(&child->load_lock);` çağrısı yaparak beklemeye geçer.
*   Diğer taraftan, yeni oluşturulan çocuk süreç `start_process()` fonksiyonunu çalıştırır. Bu fonksiyonun içinde `load()` çağrılarak çalıştırılabilir dosya yüklenmeye çalışılır.
*   `load()` fonksiyonu tamamlandıktan sonra (başarılı veya başarısız), `start_process()` fonksiyonu `sema_up(&thread_current()->load_lock);` çağrısı yapar. `thread_current()` burada çocuk süreci işaret eder.
*   Bu `sema_up` işlemi, `process_execute()` içindeki `sema_down` bekleyişini sonlandırır. Dolayısıyla, `process_execute` fonksiyonu (ve dolayısıyla `EXEC` sistem çağrısı), çocuk sürecin `load()` işlemini tamamlayıp `load_lock` semaforunu serbest bırakmasına kadar dönemez.

Kod parçacıkları:
`process.c` içinde `process_execute()`:
```c
// ... çocuk thread oluşturulur (tid) ve child işaretçisi ayarlanır ...
struct thread* child = NULL;
// ... (child_list'ten çocuğu bulma)

sema_down(&child->load_lock); // Yüklemenin tamamlanmasını bekle

// ... (yükleme sonucuna göre işlem yap)
```

`process.c` içinde `start_process()`:
```c
// ...
success = load (file_name, &if_.eip, &if_.esp);
// ...
palloc_free_page (file_name);

sema_up(&thread_current()->load_lock); // Ebeveyni uyandır, yükleme bitti
if (!success) EXIT(-1); // Yükleme başarısızsa çık
// ...
```

**2. Yükleme Başarı/Durum Bilgisinin İletilmesi:**

Yükleme işleminin başarı veya başarısızlık durumu, `EXEC` çağrısını yapan ebeveyn sürece şu şekilde iletilir:

*   Eğer `start_process()` içindeki `load()` fonksiyonu başarısız olursa (`success == false`), `start_process()` hemen ardından `EXIT(-1)` çağırır. `EXIT` sistem çağrısı, çocuğun `thread` yapısındaki `exit_status` alanını -1 olarak ayarlar.
*   Ebeveyn süreçteki `process_execute()`, `sema_down(&child->load_lock)`'tan uyandıktan sonra, çocuğun `exit_status` değerini kontrol eder.
    ```c
    // process_execute() içinde, sema_down sonrası:
    if(child->exit_status == -1) return process_wait(tid); // Yükleme başarısız, -1 döndür
    return tid; // Yükleme başarılı, çocuk sürecin tid'sini döndür
    ```
*   Eğer `child->exit_status == -1` ise, bu yüklemenin başarısız olduğu anlamına gelir. Bu durumda `process_execute`, `process_wait(tid)` çağırır. `process_wait`, sonlanmış olan çocuğun `exit_status` değerini (-1) alır ve bunu döndürür. Böylece `EXEC` sistem çağrısı -1 döndürmüş olur.
*   Eğer `load()` başarılıysa, `start_process()` `EXIT(-1)` çağırmaz ve çocuk süreç normal şekilde çalışmaya başlar. Bu durumda `child->exit_status` (eğer daha önce ayarlanmadıysa) -1 olmaz. `process_execute()` bu durumu fark eder ve çocuğun `tid` (thread ID) değerini döndürür, bu da `EXEC` için başarılı bir sonucu gösterir.

Bu mekanizma, `EXEC`'in hem senkron bir şekilde yüklemenin bitmesini beklemesini hem de yükleme sonucunu (başarı için `tid`, başarısızlık için -1) doğru bir şekilde çağıran sürece iletmesini sağlar.

>> B8: P ana işlemi ile C çocuk işlemi düşünün. P, C çıkmadan önce wait(C) çağırırken doğru senkronizasyonu ve yarış durumlarını nasıl engellersiniz?
>> C çıktıktan sonra nasıl? Her iki durumda da tüm kaynakların serbest bırakılmasını nasıl sağlarsınız? P, beklemeden C çıkmadan önce yada 
>> C çıktıktan sonra terminasyon yaparsa ne olur? Özel durumlar var mı?

P (ebeveyn) ve C (çocuk) işlemleri arasındaki senkronizasyon ve kaynak yönetimi, `wait` ve `exit` sistem çağrılarının doğru çalışması için kritik öneme sahiptir. Kullandığımız yaklaşım, `thread` yapısına eklediğimiz semaforlar (`child_lock` ve `mem_lock`) ve listeler (`child_list`, `child_elem`) üzerine kuruludur.

**Durum 1: P, C Çıkmadan Önce `wait(C)` Çağırırsa:**

1.  P, `wait(C)` çağrısı yapar. `process_wait(C_tid)` fonksiyonu çalışır.
2.  P, kendi `child_list`'inde C'yi bulur.
3.  P, C'nin `child_lock` semaforunda `sema_down(&C->child_lock)` yaparak beklemeye başlar. Bu semafor, C oluşturulurken 0 değeriyle başlatıldığı için P burada bloke olur.
4.  Bir süre sonra C, işini bitirir ve `EXIT(status)` çağırır. Bu, `process_exit()` fonksiyonunu tetikler.
5.  C, `process_exit()` içinde kendi `exit_status` değerini ayarlar.
6.  C, `sema_up(&C->child_lock)` çağrısı yapar. Bu, P'yi `sema_down` bekleyişinden uyandırır.
7.  P uyanır, `process_wait` içinde C'nin `exit_status` değerini okur.
8.  P, C'yi kendi `child_list`'inden `list_remove(&C->child_elem)` ile çıkarır.
9.  P, C'nin kaynaklarını serbest bırakabilmesi için `sema_up(&C->mem_lock)` çağrısı yapar.
10. C, `process_exit()` fonksiyonunun sonunda `sema_down(&C->mem_lock)` ile beklemektedir. P'nin yaptığı `sema_up` sayesinde C uyanır ve kendi `thread` yapısını ve diğer son kaynaklarını (örneğin, sayfa tablosu) güvenle serbest bırakabilir.

*Yarış Durumları ve Engelleme:* Bu senaryoda, `child_lock` semaforu, P'nin C'nin çıkış durumunu okumadan önce C'nin gerçekten sonlanmasını beklemesini garanti eder. `mem_lock` semaforu ise, P, C'nin bilgilerini (çıkış durumu gibi) okuyup `child_list`'ten çıkardıktan sonra C'nin kendi yapısını serbest bırakmasını sağlar. Bu, C'nin `thread` yapısının P tarafından hala kullanılırken C tarafından serbest bırakılması gibi bir yarış durumunu engeller.

**Durum 2: P, C Çıktıktan Sonra `wait(C)` Çağırırsa:**

1.  C, işini bitirir ve `EXIT(status)` çağırır (`process_exit()` çalışır).
2.  C, `exit_status` değerini ayarlar.
3.  C, `sema_up(&C->child_lock)` yapar. `C->child_lock` değeri 1 olur.
4.  C, `process_exit()` sonunda `sema_down(&C->mem_lock)` yaparak P'nin kendisini beklemesini ve çıkış durumunu almasını bekler. C burada bloke olur.
5.  Daha sonra P, `wait(C)` çağrısı yapar.
6.  P, kendi `child_list`'inde C'yi bulur (C listeden henüz çıkarılmamıştır).
7.  P, `sema_down(&C->child_lock)` çağırır. `C->child_lock` değeri 1 olduğu için P bloke olmaz, semaforun değeri 0 olur ve P devam eder.
8.  P, C'nin `exit_status` değerini okur.
9.  P, C'yi kendi `child_list`'inden çıkarır.
10. P, `sema_up(&C->mem_lock)` çağrısı yapar.
11. C, `sema_down(&C->mem_lock)` bekleyişinden uyanır ve kaynaklarını serbest bırakır.

*Yarış Durumları ve Engelleme:* Bu durumda da senkronizasyon doğrudur. C, P `wait` çağırana kadar `mem_lock` üzerinde bekleyerek kaynaklarını tutar. P `wait` çağırdığında, `child_lock` sayesinde C'nin zaten çıkmış olduğunu anlar ve durumu alıp `mem_lock`'ı serbest bırakarak C'nin temizlenmesine izin verir.

**Kaynakların Serbest Bırakılması:**
*   **C (Çocuk):** `process_exit()` içinde, C kendi açık dosyalarını kapatır. Sayfa tablosu gibi kaynaklar da burada serbest bırakılır. `thread` yapısının kendisi ise, P'nin `wait` ile çıkış durumunu alıp `mem_lock`'ı serbest bırakmasından sonra temizlenir.
*   **P (Ebeveyn):** P, `wait` sırasında C'yi kendi `child_list`'inden çıkararak C ile olan ilişkisel bağını koparır.

**P'nin Beklemeden Önce veya Sonra Termine Olması Durumları:**

1.  **P, C Çıkmadan Önce ve `wait(C)` Çağırmadan Termine Olursa:**
    *   P `process_exit()` çağırır. P'nin `child_list`'i ve diğer kaynakları serbest bırakılır.
    *   C "yetim" (orphan) kalır. C'nin `parent_thread` işaretçisi artık geçersiz bir `thread` yapısına işaret ediyor olabilir.
    *   C işini bitirip `EXIT` çağırdığında, `sema_up(&C->child_lock)` yapar. Ancak P artık beklemediği için bu `sema_up`'ın bir etkisi olmaz.
    *   C, `sema_down(&C->mem_lock)` üzerinde sonsuza kadar bloke olabilir, çünkü P `wait` çağırıp `mem_lock`'ı `up` yapmayacaktır. Bu durum, C'nin bir "zombi" sürecine dönüşmesine (kaynakları tam serbest bırakılamamış) yol açar. Bu, projemizin mevcut implementasyonunda bir zayıflıktır. İdeal bir sistemde, yetim süreçler `init` süreci gibi özel bir süreç tarafından "evlat edinilir" ve `wait` edilir veya sistem bu durumu farklı şekilde yönetir.

2.  **P, C Çıktıktan Sonra ve `wait(C)` Çağırmadan Termine Olursa:**
    *   C çıkmıştır, `exit_status`'unu ayarlamış, `child_lock`'ını `up` etmiş ve `mem_lock` üzerinde beklemektedir.
    *   P `process_exit()` çağırır. P'nin `child_list`'i serbest bırakılır.
    *   C, `mem_lock` üzerinde sonsuza kadar beklemeye devam eder, çünkü P `wait` çağırıp `mem_lock`'ı `up` yapmayacaktır. Bu da C'nin zombi olmasına neden olur.

**Özel Durumlar ve İyileştirmeler:**
*   **Zombi Süreçler:** Yukarıda belirtilen P'nin `wait` çağırmadan önce sonlanması durumları zombi süreçlere yol açar. Bu, `thread` yapılarının ve ilişkili bazı kaynakların sızmasına neden olabilir. Gerçek dünya sistemlerinde bu durumlar için daha karmaşık çözümler (re-parenting, sinyaller vb.) bulunur.
*   **Birden Fazla `wait` Çağrısı:** `process_wait` implementasyonumuz, bir çocuk için başarılı bir `wait` çağrısından sonra çocuğu `child_list`'ten çıkardığı için, aynı çocuk için sonraki `wait` çağrıları çocuğu bulamayacak ve -1 döndürecektir. Bu, beklenen davranıştır.
*   **Geçersiz PID ile `wait`:** Eğer P, kendi çocuğu olmayan bir PID veya geçersiz bir PID ile `wait` çağırırsa, `child_list`'te bulunamayacağı için -1 döner.

Projemizdeki senkronizasyon, temel `wait`/`exit` etkileşimlerini doğru bir şekilde ele alır, ancak yetim/zombi süreç yönetimi gibi daha gelişmiş senaryolar için ek mekanizmalar gerektirebilir.

---- GEREKÇE ----

>> B9: Kullanıcı belleğine çekirdekten erişimi, seçtiğiniz şekilde implement etmenizin nedeni nedir?

Kullanıcı belleğine çekirdekten erişimi implement ederken benimsediğimiz temel strateji, B3 ve B6 bölümlerinde detaylandırıldığı gibi, iki ana mekanizmaya dayanmaktadır: proaktif adres doğrulama ve donanım tabanlı sayfa hatası yönetimi.

Bu yaklaşımı seçmemizin nedenleri şunlardır:

1.  **Güvenlik ve Kararlılık Önceliği:** İşletim sistemi çekirdeğinin en temel görevlerinden biri sistemin bütünlüğünü ve kararlılığını korumaktır. Kullanıcı tarafından sağlanan işaretçiler her zaman güvenilmez olabilir. Doğrudan, kontrolsüz erişimler çekirdeğin çökmesine veya güvenlik açıklarına yol açabilir. `VERIFY_ADDR()` makromuz ile kullanıcı adreslerinin en azından temel geçerlilik (kullanıcı alanında mı, null değil mi) kontrollerini en başta yaparak birçok bariz hatayı engelliyoruz. Ardından, bellek erişimi sırasında oluşabilecek sayfa hatalarını (`page_fault` işleyicisi ile) yakalayıp hatalı süreci sonlandırmak, çekirdeğin kendisinin etkilenmesini önler.

2.  **Performans ve Basitlik Dengesi:** Her bir bayt erişimini çekirdek içinde manuel olarak kontrol etmek (örneğin, her `memcpy` öncesi tüm aralığı bayt bayt doğrulamak) çok maliyetli olabilirdi. Bunun yerine, donanımın MMU (Memory Management Unit) tarafından sağlanan sayfa tabanlı koruma mekanizmalarına güvenmek daha verimlidir. MMU, adres çevirisi ve erişim hakkı kontrolünü donanım hızında yapar. Bizim yaklaşımımız, bu donanım yeteneğini kullanır. Başlangıç adresini doğrularız ve ardından kopyalama işlemini başlatırız; eğer arada geçersiz bir erişim olursa, donanım bir sayfa hatası üretir ve biz de bunu yakalarız. Bu, implementasyon karmaşıklığını da azaltır.

3.  **Pintos'un Tasarım Felsefesiyle Uyum:** Pintos, öğrencilere işletim sistemi kavramlarını öğretmek için tasarlanmış bir sistemdir. Seçtiğimiz yöntem, sayfa tabloları, sanal bellek ve kesme/hata yönetimi gibi temel kavramların anlaşılmasına ve uygulanmasına olanak tanır. Kullanıcı belleğine erişimde karşılaşılan zorluklar ve bunların nasıl aşılabileceği konusunda pratik bir deneyim sunar.

4.  **Hata Yönetiminin Merkezileştirilmesi:** Sayfa hatalarını `exception.c` içindeki `page_fault` işleyicisinde merkezileştirmek, farklı sistem çağrılarında benzer hata kontrol kodlarını tekrar tekrar yazmak yerine, hatalı bellek erişimlerini tek bir noktada ele almamızı sağlar. Bu, kodun daha temiz ve yönetilebilir olmasına yardımcı olur.

Elbette, bu yaklaşımın da sınırları vardır. Örneğin, `copy_from_user` / `copy_to_user` gibi daha sofistike rutinler, kısmi kopyalamalara izin verebilir veya daha ayrıntılı hata bilgisi sağlayabilir. Ancak projemizin bu aşamasındaki gereksinimler ve Pintos'un genel yapısı göz önüne alındığında, seçtiğimiz adres doğrulama ve sayfa hatası tabanlı güvenlik mekanizmasının uygun bir denge sunduğunu düşünüyoruz.

>> B10: Dosya tanımlayıcıları tasarımınızın avantajlarını veya dezavantajlarını nasıl görüyorsunuz?

>> B11: Varsayılan tid_t'den pid_t'ye yapılan eşleme kimlik eşlemesidir.
>> Eğer bunu değiştirdiyseniz, yaklaşımınızın avantajları nelerdir?
