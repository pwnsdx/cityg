/// Thin convenience wrapper mimicking the Python MultiDimArray helper used in SmallWood.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Array<T> {
    data: Vec<T>,
    shape: Vec<usize>,
}

impl<T: Clone + Default> Array<T> {
    /// Create an array filled with `T::default()` for the given shape (row-major order).
    pub fn zeros(shape: &[usize]) -> Self {
        let size = shape.iter().product::<usize>();
        Self {
            data: vec![T::default(); size],
            shape: shape.to_vec(),
        }
    }
}

impl<T> Array<T> {
    pub fn from_vec(data: Vec<T>, shape: &[usize]) -> Self {
        assert_eq!(data.len(), shape.iter().product::<usize>());
        Self {
            data,
            shape: shape.to_vec(),
        }
    }

    pub fn into_vec(self) -> Vec<T> {
        self.data
    }

    pub fn as_slice(&self) -> &[T] {
        &self.data
    }

    pub fn shape(&self) -> &[usize] {
        &self.shape
    }

    fn index_to_offset(&self, indices: &[usize]) -> usize {
        assert_eq!(indices.len(), self.shape.len());
        let mut offset = 0;
        let mut stride = 1;
        for (idx, dim) in indices.iter().zip(self.shape.iter()).rev() {
            assert!(*idx < *dim);
            offset += idx * stride;
            stride *= *dim;
        }
        offset
    }

    pub fn get(&self, indices: &[usize]) -> &T {
        let offset = self.index_to_offset(indices);
        &self.data[offset]
    }

    pub fn get_mut(&mut self, indices: &[usize]) -> &mut T {
        let offset = self.index_to_offset(indices);
        &mut self.data[offset]
    }
}

#[cfg(test)]
mod tests {
    use super::Array;

    #[test]
    fn test_array_indexing() {
        let mut arr = Array::from_vec((0..6).collect::<Vec<_>>(), &[2, 3]);
        assert_eq!(*arr.get(&[1, 2]), 5);
        *arr.get_mut(&[0, 1]) = 42;
        assert_eq!(*arr.get(&[0, 1]), 42);
    }
}
