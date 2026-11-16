# Esquema e proveniência

## Camadas de arquivo

| Camada | Formato | Conteúdo |
|---|---|---|
| Relatórios históricos | JSON dos autores | Dados brutos fixados por commit e SHA-256 |
| Relatórios novos | JSON em `pilotos/` | Saídas independentes dos scanners, por aplicação e alvo |
| Normalização | `data/normalized/*.json` e CSV | Uma linha por unidade de decisão, com vínculos por ID |
| Referência | `data/ground_truth/*.csv` | Caso, CWE, camada ou artefato, observações de detecção |
| Saída de decisão | `results/*.csv` | Parâmetros, bloqueios por classe e estágio, IDs cobertos |
| Validação P4 | JSON e CSV | Evidência HTTP de cada teste, configuração e hash |

## Campos de uma unidade

| Campo | Interpretação |
|---|---|
| `id`, `ferramenta`, `identificador_scanner` | ID local, nome do scanner e identificador reportado. Uma regra ou CVE pode aparecer em várias unidades. |
| `camada`, `estagio` | APP ou INFRA e Commit, Build ou Deploy. |
| `classe`, `vinculos` | Classe global e mapa de vulnerabilidades → classe por par. As classes são direta, indireta e sem matriz. |
| `score`, `origem_score`, `severidade_original` | Pontuação comparada ao limiar, procedência da pontuação, rótulo reportado. JSON `null` representa valor ausente. |
| `cwes`, `granularidade` | CWEs reportados e unidade individual ou agregada. |
| `referencia` | Relatório relativo e localizador JSON. Para Trivy agregado, a tabela de composição identifica os membros. |

Uma unidade pode ter zero ou vários vínculos. O mesmo CWE pode identificar vários casos. Um evento de deploy acrescentado por P4 é uma decisão associada ao teste confirmado, fora das 226 unidades de entrada. Registre a versão da aplicação separadamente, com tag e commit ou digest, e a versão da ferramenta no relatório ou no manifesto do piloto. Use `data/templates/achados.csv` para novas bases e preserve JSON bruto. O CSV usa UTF-8. Os CSVs gerados usam BOM para facilitar a abertura no Excel.

`trivy_composicao.csv` referencia cada ocorrência histórica, com score, CWEs e participação em cada grupo. A presença em mais de um grupo é esperada.

Uma célula vazia em `trivy_fs_ocorrencias` significa que o scanner terminou sem identificar artefatos de dependências. Ocorrências iguais a zero exigem ao menos um artefato efetivamente avaliado. Entrada `nao_executada` na P4 significa que ainda não existe um teste com laudo para aquele caso. A ausência de score fica explícita na origem e no campo de pontuação.
