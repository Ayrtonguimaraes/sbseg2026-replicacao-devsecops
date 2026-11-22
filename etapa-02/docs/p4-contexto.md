# P4 com contexto de execução: protocolo registrado antes do cálculo

**Registrado em 22/11/2026, depois de um piloto qualitativo e antes de qualquer resultado
numérico.** Substitui a P4 de "confirmação dirigida" como proposta do grupo. O motivo está em
`p4-avaliacao.md` e resumido abaixo.

## 1. Por que a P4 anterior não é uma melhoria

1. **Já estava no artigo.** O Deploy Gate do artigo bloqueia "exploração confirmada" por DAST
   ou "testes customizados", e o teste de credenciais dos autores já é um achado direto que
   bloqueia na P3. Uma confirmação da P4 antiga é só mais um teste customizado na P3.
2. **O sinal que abria a fila não tinha informação.** A fila abria com CVEs de bibliotecas do
   sistema que só coincidiam no CWE (gnupg com CWE-352 para o CSRF da DVWA; curl com CWE-306
   para o reset do TeaStore). O teste confirmava o caso da matriz, nunca o CVE.
3. **Dependia da matriz de referência**, que um pipeline real não tem.

Os testes executados continuam válidos, mas como **o Deploy Gate do artigo efetivamente
executado** (chamado aqui de P3\*), e não como uma política nova.

## 2. A mudança de arquitetura

O artigo trata todo achado indireto do mesmo jeito: informativo no Build. Ele mesmo diz que o
componente "pode nunca ser invocado" e deixa como trabalho futuro "incorporar características
dos achados como refinamento intraclasse".

Proposta: **um coletor de contexto de execução no portão de Deploy.** Com a aplicação
implantada em homologação, o coletor registra quais pacotes os processos da aplicação de fato
carregaram (bibliotecas mapeadas em memória, arquivos abertos, executáveis em execução e, em
Node.js, os módulos carregados). Cada achado indireto do Build é reclassificado:

- **indireto em uso**: o pacote vulnerável está carregado pela aplicação em execução;
- **indireto latente**: o pacote está na imagem, mas não foi carregado.

**P4 (contexto de execução) = P3\* + bloqueio, no Deploy, dos achados indiretos em uso com
nota ≥ 7.** Os latentes continuam informativos, como na P3.

A decisão sai do Build (estático) e passa para o Deploy (com o contexto da implantação), e
não depende da matriz de referência: depende só do relatório do scanner e da observação do
contêiner.

## 3. Coleta (definida antes)

- Alvos: DVWA (mesma imagem e digest do artefato dos autores), TeaStore 1.4.2 (7 serviços) e
  Juice Shop 19.0.0, todos locais em `127.0.0.1`.
- Duas observações por alvo: S1 logo após a aplicação responder e S2 depois de tráfego benigno
  (GET nas páginas públicas, sem payload de ataque). Pacote em uso = carregado em S1 ou S2.
  A diferença entre S1 e S2 é reportada como medida de estabilidade.
- Mapeamento arquivo → pacote: banco do dpkg do próprio contêiner (Debian/Ubuntu); caminho do
  `.jar` (Java); caminho do executável (binários Go); caminho do módulo em `node_modules`
  (Node.js, por um hook de `require` injetado só no contêiner de teste).

## 4. Métricas e critérios (definidos antes)

Por alvo: achados indiretos com nota ≥ 7 (os que a P2 bloqueia e a P3 não); quantos estão em
uso e quantos latentes; bloqueios e cobertura bruta de P2, P3, P3\* e P4.

- **Critério de utilidade do coletor:** a fração em uso entre os indiretos ≥ 7 fica entre 10%
  e 90% em pelo menos 2 dos 3 alvos. Fora disso o coletor não discrimina, e a P4 se reduz à P2
  ou à P3.
- **Critério de estabilidade:** S1 e S2 classificam igual pelo menos 90% dos indiretos ≥ 7.
- **Leitura do resultado:** reportar quantos bloqueios da P2 recaem sobre pacotes latentes
  (bloqueios que a P4 evita com evidência) e quantos casos da matriz a P4 cobre a mais que a
  P3\*. A cobertura obtida via indireto em uso continua sendo coincidência de CWE e será
  reportada como tal.

## 5. Limites conhecidos antes da coleta

- Carregado não é o mesmo que a função vulnerável ser alcançada; é um filtro necessário, não
  suficiente.
- Bibliotecas carregadas só sob certos fluxos podem aparecer como latentes (falso negativo).
  O tráfego benigno reduz, mas não elimina, esse risco.
- As imagens são amd64 e rodam emuladas (Rosetta) nesta máquina; o carregamento de bibliotecas
  não depende da arquitetura.

## Resultados

*(preenchido em commit posterior)*
