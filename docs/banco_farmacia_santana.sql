-- =====================================================
-- Banco de dados: Farmácia Santana (controle de estoque)
-- SGBD: MySQL 8+ / MariaDB (adaptável para PostgreSQL)
-- =====================================================
CREATE DATABASE IF NOT EXISTS farmacia_santana CHARACTER SET utf8mb4;
USE farmacia_santana;

-- 1) Usuários do sistema (perfis de acesso)
CREATE TABLE usuarios (
  id INT AUTO_INCREMENT PRIMARY KEY,
  nome VARCHAR(100) NOT NULL,
  email VARCHAR(120) NOT NULL UNIQUE,
  senha_hash VARCHAR(255) NOT NULL,
  perfil ENUM('gerente','farmaceutico','balconista') NOT NULL DEFAULT 'balconista',
  ativo BOOLEAN NOT NULL DEFAULT TRUE
);

-- 2) Categorias
CREATE TABLE categorias (
  id INT AUTO_INCREMENT PRIMARY KEY,
  nome VARCHAR(60) NOT NULL UNIQUE,
  exige_receita BOOLEAN NOT NULL DEFAULT FALSE
);

-- 3) Fornecedores
CREATE TABLE fornecedores (
  id INT AUTO_INCREMENT PRIMARY KEY,
  razao_social VARCHAR(120) NOT NULL,
  cnpj CHAR(14) NOT NULL UNIQUE,
  telefone VARCHAR(20),
  email VARCHAR(120)
);

-- 4) Produtos (cadastro geral)
CREATE TABLE produtos (
  id INT AUTO_INCREMENT PRIMARY KEY,
  nome VARCHAR(120) NOT NULL,
  codigo_barras VARCHAR(20) UNIQUE,
  categoria_id INT NOT NULL,
  estoque_minimo INT NOT NULL DEFAULT 5 CHECK (estoque_minimo >= 0),
  preco_venda DECIMAL(10,2) NOT NULL CHECK (preco_venda >= 0),
  FOREIGN KEY (categoria_id) REFERENCES categorias(id)
);

-- 5) Lotes (controle de validade e custo por lote)
CREATE TABLE lotes (
  id INT AUTO_INCREMENT PRIMARY KEY,
  produto_id INT NOT NULL,
  fornecedor_id INT NOT NULL,
  numero_lote VARCHAR(40) NOT NULL,
  validade DATE NOT NULL,
  quantidade INT NOT NULL DEFAULT 0 CHECK (quantidade >= 0),
  custo_unitario DECIMAL(10,2) NOT NULL CHECK (custo_unitario >= 0),
  UNIQUE (produto_id, numero_lote),
  FOREIGN KEY (produto_id) REFERENCES produtos(id),
  FOREIGN KEY (fornecedor_id) REFERENCES fornecedores(id)
);

-- 6) Movimentações (histórico de entradas e saídas)
CREATE TABLE movimentacoes (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  lote_id INT NOT NULL,
  usuario_id INT NOT NULL,
  tipo ENUM('entrada','saida','descarte') NOT NULL,
  quantidade INT NOT NULL CHECK (quantidade > 0),
  numero_receita VARCHAR(40),
  data_hora DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (lote_id) REFERENCES lotes(id),
  FOREIGN KEY (usuario_id) REFERENCES usuarios(id)
);

CREATE INDEX idx_lotes_validade ON lotes(validade);
CREATE INDEX idx_mov_data ON movimentacoes(data_hora);

-- =====================================================
-- TRIGGER: atualiza o estoque do lote e impede saída inválida
-- =====================================================
DELIMITER //
CREATE TRIGGER trg_movimentacao_antes
BEFORE INSERT ON movimentacoes FOR EACH ROW
BEGIN
  DECLARE v_qtd INT; DECLARE v_val DATE; DECLARE v_exige BOOLEAN;
  SELECT l.quantidade, l.validade, c.exige_receita
    INTO v_qtd, v_val, v_exige
    FROM lotes l
    JOIN produtos p ON p.id = l.produto_id
    JOIN categorias c ON c.id = p.categoria_id
   WHERE l.id = NEW.lote_id;

  IF NEW.tipo = 'saida' THEN
    IF NEW.quantidade > v_qtd THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Estoque insuficiente';
    END IF;
    IF v_val < CURDATE() THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Lote vencido: venda bloqueada';
    END IF;
    IF v_exige AND NEW.numero_receita IS NULL THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Receita obrigatória';
    END IF;
  END IF;

  IF NEW.tipo = 'entrada' THEN
    UPDATE lotes SET quantidade = quantidade + NEW.quantidade WHERE id = NEW.lote_id;
  ELSE
    UPDATE lotes SET quantidade = quantidade - NEW.quantidade WHERE id = NEW.lote_id;
  END IF;
END//
DELIMITER ;

-- =====================================================
-- VIEWS para o painel
-- =====================================================
CREATE VIEW vw_estoque_produto AS
SELECT p.id, p.nome, c.nome AS categoria, p.estoque_minimo,
       COALESCE(SUM(l.quantidade),0) AS estoque_total,
       COALESCE(SUM(l.quantidade * l.custo_unitario),0) AS valor_custo
  FROM produtos p
  JOIN categorias c ON c.id = p.categoria_id
  LEFT JOIN lotes l ON l.produto_id = p.id
 GROUP BY p.id, p.nome, c.nome, p.estoque_minimo;

CREATE VIEW vw_estoque_baixo AS
SELECT * FROM vw_estoque_produto WHERE estoque_total <= estoque_minimo;

CREATE VIEW vw_vencimentos AS
SELECT p.nome, l.numero_lote, l.validade, l.quantidade,
       DATEDIFF(l.validade, CURDATE()) AS dias_para_vencer
  FROM lotes l JOIN produtos p ON p.id = l.produto_id
 WHERE l.quantidade > 0 AND l.validade <= DATE_ADD(CURDATE(), INTERVAL 30 DAY)
 ORDER BY l.validade;

-- =====================================================
-- DADOS DE EXEMPLO
-- =====================================================
INSERT INTO categorias (nome, exige_receita) VALUES
 ('Medicamento',FALSE),('Genérico',FALSE),('Controlado',TRUE),('Higiene',FALSE);
INSERT INTO usuarios (nome,email,senha_hash,perfil) VALUES
 ('Gerente Santana','gerente@santana.com','HASH_AQUI','gerente');
INSERT INTO fornecedores (razao_social,cnpj) VALUES ('Distribuidora Saúde Ltda','12345678000199');
INSERT INTO produtos (nome,categoria_id,estoque_minimo,preco_venda) VALUES
 ('Dipirona 500mg',2,20,6.50),('Clonazepam 2mg',3,5,18.90);
INSERT INTO lotes (produto_id,fornecedor_id,numero_lote,validade,quantidade,custo_unitario) VALUES
 (1,1,'L001','2027-06-30',100,3.20),(2,1,'L778','2027-01-15',30,9.50);

-- Consultas úteis
-- SELECT * FROM vw_estoque_baixo;
-- SELECT * FROM vw_vencimentos;
-- INSERT INTO movimentacoes (lote_id,usuario_id,tipo,quantidade) VALUES (1,1,'saida',2);

-- =====================================================
-- RECUPERAÇÃO DE SENHA POR E-MAIL (código de 6 dígitos)
-- =====================================================
CREATE TABLE recuperacao_senha (
  id INT AUTO_INCREMENT PRIMARY KEY,
  usuario_id INT NOT NULL,
  codigo_hash VARCHAR(255) NOT NULL,
  expira_em DATETIME NOT NULL,
  usado BOOLEAN NOT NULL DEFAULT FALSE,
  criado_em DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (usuario_id) REFERENCES usuarios(id)
);
-- Fluxo no servidor: gerar código -> gravar hash + expira_em (10 min)
-- -> enviar por e-mail (SMTP) -> validar código -> atualizar usuarios.senha_hash.
