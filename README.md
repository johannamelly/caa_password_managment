# CAA - labo 5

###### Auteur: Johanna Melly

###### Date: 29.04.19

## Guideline

En lançant le programme, l'utilsateur peut se retrouver dans 2 situations différentes:

- Soit c'est la première fois qu'il utilise le programme et il lui est demandé d'entrer un nouveau master password
- Soit il a déjà utilisé le programme auparavant et il lui est demandé d'entrer son mater password

Si le master password est correct, alors l'utilisateur est connecté. Un menu s'affiche:

```bash
What's your choice?
1 - Add password
2 - Find password
3 - List all entries
4 - Change master password
5 - Lock
6 - Quit
```

L'utilisateur peut entrer un des index pour effectuer l'action correspondante.

`Add password` permet d'entrer un nouveau mot de passe. L'utilisateur doit entrer le nom sous lequel il souhaite l'enregistrer et le mot de passe.

`Find password` permet de retrouver un mot de passe précédemment enregistré. L'utilisateur donne le nom de l'entrée et le mot de passe correspondant est affiché.

`List all entries` permet de lister toutes les noms des mots de passe stockés.

`Change master password` permet de changer le master password. L'utilisateur entre le nouveau master password et est déconnecté.

`Lock` permet de vérouiller l'application. Pour la dévérouiller, l'utilisateur devra entrer son master password.

`Quit` quitte le programme.

## Rapport

### Choix

#### Hashing du master password

Pour le hashing du master password, l'algorithme Argon2id est utilisé, avec les paramètres d'opérations maximum à 20 et de mémoire à _sensitive_. C'est un algorithme très sûr. Comme le master password n'est généré / vérifié qu'une fois par session, ce n'est pas trop contraignant pour l'utilisateur d'attendre plusieurs seconde que le hashing / la véréfication se fasse et cela garantit une meilleure sécurité.

#### Chiffrement des mots de passe

Pour le chiffrement, j'ai opté pour ChaCha20, qui est sûr et rapide, ce qui est aussi important pour le confort de l'utilisateur. ChaCha20 demande l'utilisation d'une clé, qui est dérivée du master password. 

#### Allocations mémoire

Pour les allocations, j'ai utilisé, lorsqu'il fallait manipuler le mot de passe non chiffré de l'utilisateur, la fonction d'allocation mémoire `sodium_malloc` de Libsodium couplée à leur fonction `sodium_mlock` qui permet d'éviter le swapping mémoire. Pour libérer les pointeurs aloués de cette manière, j'ai utilisé les fonctions `sodium_munlock` et `sodium_free`.

Pour les pointeurs qui n'étaient pas critiques, j'ai utilisé la fonction `malloc`.

```c
void* locked_allocation(size_t nb_bytes){

    void* mem = sodium_malloc(nb_bytes);

    if(mem == NULL){
        printf("Something went wrong %s\n", strerror(errno));
        return NULL;
    }
    if(sodium_mlock(mem, nb_bytes)){
        printf("Something went wrong %s\n", strerror(errno));
        sodium_free(mem);
        return NULL;
    }
    return mem;
}

void * free_buffer(void* mem, size_t nb_bytes) {
    sodium_munlock(mem, nb_bytes);
    sodium_free(mem);
```

### Liste des différents fichiers

- `allPW.txt` liste de tous les mots de passe. Contient: le nom de l'entrée, le mot de passe chiffré puis encodé en base64 et le nonce encodé en base64.
- `masterPW.txt` contient le master password hashé.
- `salt.txt` contient le sel généré avec la clé de chiffrement et déchiffrement.

### Description du programme

#### Première utilisation

Si, lors du lancement du programme, le fichier `masterPW.txt` est vide, c'est qu'aucun master password n'a été défini et donc qu'il s'agit de la première utilisation du programme.

Un master password va être demandé à l'utilisateur. Pour éviter qu'un utilisateur ait supprimé le fichier `masterPW.txt` afin de redéfinir un master password et accéder à la liste des mots de passe, le fichier `allPW.txt` est supprimé.

Le master password est ensuite hashé à l'aide d'Argon2id avec les paramètres d'opérations maximum à 20 et de mémoire à _sensitive_. Enfin, ce hash est stocké dans un fichier nommé `masterPW.txt`.

Comme il s'agit de la première utilisation, cela signifie qu'il n'y a pas non plus de clé pour le chiffrement symétrique des mots de passe. Un clé est donc dérivée à partir du master password (en clair) et d'un sel, à l'aide d'une key derivation function. La clé est ensuite renvoyée en retour de fonction et va pouvoir être utilisée à chaque chiffrement et déchiffrement de mot de passe.

#### Connexion

Si l'utilisateur a déjà un master password, alors il va lui être demandé. Lorsque l'utilisateur entre un master password, il est vérifié à l'aide d'une fonction de vérification Argon2id. Tant que l'utilisateur échoue à entrer le bon mot de passe, le programme reste locké et lui demande son master password.

Si l'utilisateur entre le bon mot de passe, alors sa clé de chiffrement est récupérée.

#### Stockage de mots de passe

Lorsqu'un utilisateur souhaite stocker un mot de passe, le programme lui demande le nom de l'entrée ainsi que le mot de passe lui même. Le mot de passe est récupéré dans un pointeur avec allocation mémoire sodium.

Un nonce est généré à l'aide de la fonction de Libsodium `randombytes_buf` générant des bytes aléatoires.  Le nonce, la master key (passée en paramètre) et le mot de passe entrés par l'utilisateur sont passés à la fonction de chiffrement ChaCha20. 

```c
crypto_aead_chacha20poly1305_encrypt(ciphertext, &ciphertext_len,
                                     password, strlen((char*)password),
                                     NULL, 0,
                                     NULL, nonce, key);
```

Le stockage dans le fichier `allPW.txt `s'effectue ainsi:

NOUVELLE LIGNE | NOM DE L'ENTRÉE | TABULATION | MOT DE PASSE CHIFFRÉ ENCODÉ EN BASE64 | TABULATION | NONCE ENCODÉ EN BASE64

Le ciphertext et le nonce sont encodés en base64 grâce à la fonction `sodium_bin2base64`, pour permettre d'utiliser un séparateur (ici une tabulation) qui permettra de récupérer chaque élément séparément dans le fichier. Si le ciphertext et le nonce étaient stockés tels quels, pourrait s'y trouver une tabulation qui empêcherait une séparation correcte du fichier.

#### Récupération d'un mot de passe

Le programme demande à l'utilisateur le nom de l'entrée dont il veut récupérer le mot de passe. Le fichier `allPW.txt`est parcouru jusqu'à trouver l'entrée correspondante et le cipher et le nonce sont récupérés. S'il n'y a aucune entrée correspondante, les pointeurs sont libérés et la méthode se termine. Sinon, le cipher et le nonce sont décodéss depuis la base64.

Le mot de passe est ensuite déchiffré.

```c
if (crypto_aead_chacha20poly1305_decrypt(password, &password_len,
                                         NULL,
                                         cipherDecoded, strlen((char*)cipherDecoded),
                                         NULL,
                                         0,
                                         nonceDecoded, key) != 0) {
    [...]
}
```

Si le déchiffrement s'est effectué correctement, il est finalement affiché à l'utilisateur.

#### Changement du master password

### Problèmes présents

En testant l'application, j'ai noté deux problèmes principaux dont je n'ai pas réussi à me débarrasser à temps:

- Lors de la récupération de mots de passe, certains mots de passe sont mal déchiffrés. Je n'ai pas trouvé de corrélation entre ces mots de passe. J'ai aussi bien vérifié que le ciphertext et le nonce décodés depuis la base64 correspondaient au ciphertext et au nonce tels qu'ils apparaissaient lors du chiffrement.
- Lors du changement de master password, s'il y a plus d'une dizaine de mots de passe, alors un problème d'allocation mémoire apparaît et le programme se temrine sur une segfault.



## onconc

