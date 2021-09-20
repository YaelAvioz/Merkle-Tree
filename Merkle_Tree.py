import base64
import math
from hashlib import sha256

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key


def get_hexdigest(value: bytes) -> str:
    return sha256(value).hexdigest()


class MerkleNode:

    def __init__(self, value: str, left=None, right=None):
        self.left: MerkleNode = left
        self.right: MerkleNode = right
        self.parent: MerkleNode = None
        self.value = value
        self.digest = get_hexdigest(value.encode())


class MerkleTree:

    def __init__(self):
        self.leaves: list[MerkleNode] = []
        self.root: MerkleNode = None
        self.is_left: dict[str: bool] = {}

    def _create_tree(self):
        nodes: list[MerkleNode] = self.leaves[:]
        while len(nodes) > 1:

            tmp = []
            for i in range(0, len(nodes), 2):
                if i + 1 >= len(nodes):
                    tmp.append(nodes[i])
                    break

                left = nodes[i]
                right = nodes[i + 1]
                self.is_left[left.digest] = True
                self.is_left[right.digest] = False
                parent = MerkleNode(value=(left.digest + right.digest), left=left, right=right)
                left.parent = parent
                right.parent = parent
                tmp.append(parent)
            nodes = tmp

        self.root = nodes[0]

    def set_command(self, func_number, command):
        if func_number == 1:
            self.add_leaf(command[1])

        elif func_number == 2:
            result = self.calc_root()
            if result is not None:
                print(result)
            else:
                print()

        elif func_number == 3:
            print(self.get_proof(int(command[1])))

        elif func_number == 5:
            print('{}\n{}'.format(*self.generate_keys()))

        elif func_number == 6:
            print(self.create_signature(command[1]))

        elif func_number == 7:
            print(self.verify_signature(*command[1]))

    # input 1 - Add a leaf to the Merkle tree
    def add_leaf(self, value):
        self.leaves.append(MerkleNode(value=value))
        self._create_tree()

    # input 2 - Calculates the root value
    def calc_root(self) -> str:
        if self.root:
            return self.root.digest

    # input 3 - Create Proof of Inclusion
    def _get_proof_helper(self, current_node: MerkleNode) -> str:
        if current_node == self.root:
            return ''

        brother = ('0' + current_node.parent.left.digest if current_node.parent.left != current_node
                   else '1' + current_node.parent.right.digest)

        return ' ' + brother + self._get_proof_helper(current_node.parent)

    def get_proof(self, index: int) -> str:
        if not self.root or index >= len(self.leaves) or index < 0:
            return ''
        return self.root.digest + self._get_proof_helper(self.leaves[index])

    # input 4 - Proof of Inclusion
    @staticmethod
    def check_proof_helper(value, digest_list) -> str:
        if not digest_list:
            return value

        # if the next proof is left so concat proof1 + val else, val + proof1
        if digest_list[0][0] == 0:
            concat = digest_list[0][1:] + value
        else:
            concat = value + digest_list[0][1:]

        value = get_hexdigest(concat.encode())
        return MerkleTree.check_proof_helper(value, digest_list[1:])

    @staticmethod
    def check_proof(proof: str) -> str:
        proof = proof.split()
        value = proof[0]
        digest_list = proof[2:]
        return str(MerkleTree.check_proof_helper(get_hexdigest(value.encode()), digest_list) == proof[1])

    # input 5 - Create a key (using RSA algorithm)
    @staticmethod
    def generate_keys():
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        private_pem = private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                encryption_algorithm=serialization.NoEncryption()).decode()

        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                             format=serialization.PublicFormat.SubjectPublicKeyInfo).decode()

        return private_pem, public_pem

    # input 6 - Create Signature
    def create_signature(self, sign_key: str) -> str:
        signature = load_pem_private_key(sign_key.encode(), password=None, backend=default_backend()).sign(
            self.root.digest.encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        return (base64.b64encode(signature)).decode()

    # input 7 - Verify Signature
    @staticmethod
    def verify_signature(public_key: str, signature: str, text: str) -> bool:
        public_key = load_pem_public_key(public_key.encode(), backend=default_backend())

        try:
            public_key.verify(base64.decodebytes(signature.encode()), text.encode(),
                              padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                              hashes.SHA256())
            return True

        except InvalidSignature:
            return False


class SparseNode:
    def __init__(self, value: str, index: int):
        self.value = value
        self.index = index


class SparseTree:

    def __init__(self):
        self.changed_leaves: list[SparseNode] = []
        self.default_values = []
        self.initialize_default_values_info()

    def initialize_default_values_info(self):
        val = '0'
        self.default_values.append(val)
        for i in range(256):
            val = val + val
            val = get_hexdigest(val.encode())
            self.default_values.append(val)

    # check if we already change this leaf
    @staticmethod
    def is_contain(index_num, container) -> bool:
        for node in container:
            if node.index == index_num:
                return True
        return False

    # check if this leaf is left son
    @staticmethod
    def is_left(index) -> bool:
        # if odd (1 at the end) - right leaf, else - even - left leaf
        if index % 2 == 0:
            return True
        else:
            return False

    # return the node in index - index_num in collection level
    @staticmethod
    def get_node(index_num, level) -> SparseNode:
        for node in level:
            if node.index == index_num:
                return node

    def calc_new_val(self, current_node, level, i):
        # if node is left check if his brother(the right one) has changed
        if SparseTree.is_left(current_node.index):
            brother_index = current_node.index + 1
            if SparseTree.is_contain(brother_index, level):
                brother = SparseTree.get_node(brother_index, level)
                new_value = current_node.value + brother.value
                level.remove(brother)
            # brother doesn't changed
            else:
                new_value = current_node.value + self.default_values[i]
            new_value = get_hexdigest(new_value.encode())

        # node is right check if his brother(the left one) has changed
        else:
            brother_index = current_node.index - 1
            if SparseTree.is_contain(brother_index, level):
                brother = SparseTree.get_node(brother_index, level)
                new_value = brother.value + current_node.value
                level.remove(brother)
            # brother doesn't changed
            else:
                new_value = self.default_values[i] + current_node.value
            new_value = get_hexdigest(new_value.encode())
        return new_value

    # by given list of nodes at the same leve we will calculate the level above the given one
    def calc_layer_above(self, level, i) -> list:
        above_level = []
        for node in level:
            new_index = math.floor(node.index >> 1)
            new_value = self.calc_new_val(node, level, i)
            above_level.append(SparseNode(new_value, new_index))
        return above_level

    def set_command(self, func_number, command):
        if func_number == 8:
            self.change_leaf_value(command[1])

        elif func_number == 9:
            print(self.calc_root())

        elif func_number == 10:
            print(self.get_proof(command[1]))

    # input 8 - Change Value
    def change_leaf_value(self, digest):
        index = int(digest, 16)
        # if this index already changed to 1 - pass
        if SparseTree.is_contain(index, self.changed_leaves):
            return
        # change the leaf in index
        self.changed_leaves.append(SparseNode(value='1', index=index))

    # input 9 - Change Value
    def calc_root_helper(self) -> int:
        level = self.changed_leaves.copy()
        level_above = []
        for i in range(256):
            level_above = self.calc_layer_above(level, i)
            level = level_above
        return level_above[0].value

    def calc_root(self) -> int:
        # if we didn't change the leaf (list is empty) return the 'default root'- at index 256
        if len(self.changed_leaves) == 0:
            return self.default_values[256]
        # else at least one leaf as changed - return the root value
        return self.calc_root_helper()

    # input 10 - Create Proof of Inclusion
    def get_proof_helper(self, index, level):
        proof = ''
        for i in range(256):
            # check if index node has changed
            if SparseTree.is_contain(index, level):
                # if index node is left so his brother is right
                if SparseTree.is_left(index):
                    brother_index = index + 1
                # if index node is right so his brother is left
                else:
                    brother_index = index - 1
                # check if his brother has changed
                if SparseTree.is_contain(brother_index, level):
                    brother_node = SparseTree.get_node(brother_index, level)
                    # only for the first time so that won't be double spaces
                    if proof == '':
                        proof = brother_node.value
                    else:
                        proof = proof + ' ' + brother_node.value
                # brother has not change, get default value
                else:
                    # only for the first time so that won't be double spaces
                    if proof == '':
                        proof = self.default_values[i]
                    else:
                        proof = proof + ' ' + self.default_values[i]
            # index node didn't changed, check if his brother has changed
            else:
                # if index node is left so his brother is right
                if SparseTree.is_left(index):
                    brother_index = index + 1
                # if index node is right so his brother is left
                else:
                    brother_index = index - 1

                # if his brother as changed concat the proof, else continue
                if SparseTree.is_contain(brother_index, level):
                    brother_node = SparseTree.get_node(brother_index, level)
                    # only for the first time so that won't be double spaces
                    if proof == '':
                        if i != 0:
                            proof = self.default_values[i] + ' ' + brother_node.value
                        else:
                            proof = brother_node.value
                    else:
                        proof = proof + ' ' + brother_node.value

            if i < 255:
                level_above = self.calc_layer_above(level, i)
                index = math.floor(index >> 1)
                level = level_above
                i += 1
            else:
                # the whole route was default values one side is default and the other not
                if proof == '':
                    if SparseTree.is_left(index):
                        proof = self.default_values[i] + ' ' + level[0].value
                    else:
                        proof = level[0].value + ' ' + self.default_values[i]
        return proof

    def get_proof(self, digest):
        root_val = self.calc_root()
        # if no leaf has changed return the root as proof
        if len(self.changed_leaves) == 0:
            return str(root_val) + ' ' + str(root_val)
        index = int(digest, 16)
        level = self.changed_leaves.copy()
        proof = self.get_proof_helper(index, level)
        return str(root_val) + ' ' + proof

    # input 11 - Verify Proof of Inclusion
    @staticmethod
    def calc_from_leaf_helper(index, val_leaf, val_bro):
        if SparseTree.is_left(index):
            value = val_leaf + val_bro
        else:
            value = val_bro + val_leaf
        return get_hexdigest(value.encode())

    @staticmethod
    def calc_from_leaf(index: int, proof: str):
        # calc the both leaves
        value = SparseTree.calc_from_leaf_helper(index, proof[0], proof[1])
        index = math.floor(index >> 1)
        proof = proof[2:]
        length = len(proof)
        # calc the tree
        for i in range(length):
            if SparseTree.is_left(index):
                value = value + proof[i]
            else:
                value = proof[i] + value
            value = get_hexdigest(value.encode())
            index = math.floor(index >> 1)
        return value

    @staticmethod
    def calc_index_by_len_proof(length: int, index: int) -> int:
        for i in range(256 + 2 - length):
            index = math.floor(index >> 1)
        return index

    @staticmethod
    def root_sons_proof(index: int, proof: str):
        if SparseTree.is_left(index):
            value = proof[1] + proof[2]
        else:
            value = proof[2] + proof[1]
        return get_hexdigest(value.encode())

    @staticmethod
    def _check_proof_helper(index: int, proof: str):
        length = len(proof)
        # check if we got proof from leaf, t 256 concat proofs
        if length == 257:
            return SparseTree.calc_from_leaf(index, proof)
        # if the value is 1 and we didn't get 256 concat proofs - return false
        elif proof[0] == '1':
            return False
        # we got only root sons
        elif length == 3:
            return SparseTree.root_sons_proof(index, proof)
        # we got only root
        elif length == 2:
            return proof[1]
        # we got some node
        else:
            proof = proof[1:]
            length = length - 1
            index = SparseTree.calc_index_by_len_proof(length, index)
            if SparseTree.is_left(index):
                value = proof[0] + proof[1]
            else:
                value = proof[1] + proof[0]
            value = get_hexdigest(value.encode())
            index = math.floor(index >> 1)
            length = length
            if length > 2:
                for i in range(2, length):
                    if SparseTree.is_left(index):
                        value = value + proof[i]
                    else:
                        value = proof[i] + value
            return value

    @staticmethod
    def check_proof(proof) -> bool:
        proof = proof.split()
        index = int(proof[0], 16)
        leaf_value = proof[1]
        given_root = proof[2]
        digest_list = proof[3:]
        digest_list.insert(0, leaf_value)
        return SparseTree._check_proof_helper(index, digest_list) == given_root


def main():
    mt = MerkleTree()
    st = SparseTree()
    while True:
        # get input from user
        command = input()
        # analyze and execute the command
        command = command.split(' ', 1)
        func_number = int(command[0])
        if 1 <= func_number <= 7:
            if func_number == 4:
                print(MerkleTree.check_proof(command[1]))
            elif func_number == 6:
                key = command[1] + '\n'
                command = input()
                while command:
                    key += command + '\n'
                    command = input()
                command = func_number, key
            elif func_number == 7:
                key = command[1] + '\n'
                command = input()
                while command:
                    key += command + '\n'
                    command = input()
                signature, text = input().split()
                input()
                command = func_number, (key, signature, text)
            mt.set_command(func_number, command)
        elif 8 <= func_number <= 11:
            if func_number == 11:
                print(SparseTree.check_proof(command[1]))
            st.set_command(func_number, command)
        else:
            print()


if __name__ == '__main__':
    main()
